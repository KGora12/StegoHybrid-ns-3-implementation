// scratch/channel.cc
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include "ns3/mac48-address.h"
#include "ns3/flow-monitor-module.h"
#include "ns3/data-rate.h" // dla DataRate

// Dodatkowe include'y do ARP cache
#include "ns3/arp-cache.h"
#include "ns3/ipv4-l3-protocol.h"
#include "ns3/ipv4-interface.h"
#include "ns3/node-list.h"
#include "ns3/ipv4-header.h"
#include "ns3/object-vector.h"

#include <iomanip>
#include <vector>
#include <string>
#include <iostream>
#include <algorithm>
#include <map>
#include <cstdint>
#include <cmath>
#include <random>
#include <queue>
#include <deque>
#include <unordered_map>
#include <cstring> // memcpy
#include <fstream> // CSV output

#include "stego_crypto.h"
#include "stego_mac.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("HybridTxopQam");

// ===================== GLOBAL CONFIG =====================

uint32_t SEED;
static double gSimSeconds = 300.0; // --sim=

// Transmission mode (More Data semantics from the paper):
//   0 = Only-PHY      (no MAC symbol; More Data always 0)
//   1 = TXOP Full-Usage (MAC symbol every TXOP; More Data always 1)
//   2 = Adaptive TXOP (MAC symbol only when More Data = 1)
static uint32_t gTxMode = 1;          // --mode=
// Covert encryption: 0=off, 1=ARX (Alg.1), 2=TTAK (Alg.2)
static uint32_t gCrypt = 1;           // --crypt=
// Adaptive mode: modelled More Data probability (queue backlog proxy).
// Replaced by the real header bit when using the ns-3 patch + trace sink.
static double gMoreDataProb = 0.5;    // --mdProb=
// Per-TXOP observation CSV for the detectability / steganalysis script.
static std::string gTxopCsvPath = "txop_trace.csv"; // --txopCsv=
static std::ofstream gTxopCsv;
// Real ns-3 MAC TXOP observations, separate from symbolic encoder log.
static std::string gMacTxopCsvPath = "mac_txop.csv";
static std::ofstream gMacTxopCsv;
static double gWarmupSeconds = 2.0;
// Real MAC TXOP budget control (requires apply_mac_txop_patch.py).
static bool gMacControl = true;
static std::string gMacBudgetCsvPath = "mac_budget.csv";
static std::ofstream gMacBudgetCsv;

static std::string gCovertAc = "BOTH"; // VO, VI or BOTH; independent of saturation AC
static uint32_t gRun = 1; // ns-3 reproducible RNG stream run
static double gIdleStepUs = 2256.0; // pacing when adaptive suppresses a symbol
static std::string gSatAc = "NONE"; // NONE, VO, VI, BOTH
static std::string gSatRate = "100Mbps"; // offered UDP rate PER active AC
static uint32_t gSatPacketBytes = 1000;
static uint64_t gMacVoCount = 0, gMacViCount = 0;
static double gMacVoUnusedSum = 0, gMacViUnusedSum = 0;

static void RecordMacBudget(std::string ac, Time start, Time budget,
                            uint8_t linkId, bool active) {
  double t = start.GetSeconds();
  if (t < gWarmupSeconds || t >= gWarmupSeconds + gSimSeconds) return;
  gMacBudgetCsv << ac << ',' << std::fixed << std::setprecision(9)
                << t << ',' << std::setprecision(3) << budget.GetNanoSeconds()/1000.0
                << ',' << unsigned(linkId) << ',' << (active ? 1 : 0) << '\n';
}

static void RecordMacTxop(std::string ac, double limitUs, Time start,
                          Time duration, uint8_t linkId) {
  const double t = start.GetSeconds();
  if (t < gWarmupSeconds || t >= gWarmupSeconds + gSimSeconds) return;
  const double usedUs = duration.GetNanoSeconds() / 1000.0;
  const double unusedUs = std::max(0.0, limitUs - usedUs);
  if (ac == "VO") { ++gMacVoCount; gMacVoUnusedSum += unusedUs; }
  else { ++gMacViCount; gMacViUnusedSum += unusedUs; }
  gMacTxopCsv << (gTxMode == 1 ? "full_usage" : gTxMode == 2 ? "adaptive_model" : "baseline")
      << ',' << ac << ',' << std::fixed << std::setprecision(9)
      << t << ',' << (t + duration.GetSeconds()) << ','
      << static_cast<unsigned>(linkId) << ',' << std::setprecision(3)
      << limitUs << ',' << usedUs << ',' << unusedUs << ','
      << (usedUs > limitUs ? 1 : 0) << '\n';
}


// PHY/MAC timing model for airtime (tunable to match MCS3 @ 20 MHz)
static double gAirMbps = 26.0;      // --airMbps= (MCS3 net PHY rate for payload bits)
static uint32_t gMacHdrBytes = 36;  // --macHdrB= (MAC hdr + FCS approx)
static double gPlcpUs = 120.0;      // --plcpUs= (HE preamble+SIG, us)
static double gSifsUs = 16.0;       // fixed
static double gSlotUs = 9.0;        // fixed
static double gDifsUs = 34.0;       // fixed (SIFS + 2*Slot)
static double gAvgBackoffUs = 13.5; // --bkoffUs= (~CWmin/2 * Slot for VO)
static double gAckUs = 44.0;        // --ackUs= (ACK incl. preamble, rough)

// SNR/EVM for QAM BER model
static double kSnrEsDb = 26.0; // --snrDb= (Es/N0 in dB for QAM demod)

// QAM hidden-channel model knobs
static double gStegoQuadrantHit = 0.25; // --gateHit= P(symbol quadrant matches 2 secret bits)
static double gStegoDetectProb = 0.80;  // --gateDetect= geometric/detector success (inside/outside ellipse)
static double gHiddenBerScale = 4.0;    // --hiddenBerScale= hidden BER amplification vs overt BER (approx)

// In-flight limit to avoid memory blowup (back-pressure)
static uint32_t gInflightLimit = 10; // --inflight=

// UWAGA: legBgRate traktujemy jako *główną docelową przepływność QAM* (mairate)
static std::string gLegacyBgRate = "5Mbps";   // --legBgRate= (np. 5Mbps, 0Mbps żeby wyłączyć QAM)
static uint32_t gLegacyBgPktBytes = 1000;     // zostawione tylko do CSV
static double gQamTargetBps = 5e6;            // przeliczane z gLegacyBgRate w main()

// NEW: Variable number of background stations (ordinary traffic)
// (możesz ustawić --stations i --bgRate, jeśli chcesz dodatkowe STAcje tła,
// ale nie ma już "legacy" OnOff na tej samej stacji)
static uint32_t gNumBgSta = 0;           // --stations=K
static std::string gBgRate = "25Mbps";   // --bgRate=
static uint32_t gBgPktBytes = 2000;      // --bgPktB=
static const uint16_t kBgBasePort = 10000; // base UDP port for sinks on AP

// CSV output
static std::string gCsvPath = "hybrid_cc_results.csv"; // --csv=

// NEW: pacing options
static bool gPauseTxopIfQamBackpress = true; // --pauseTxopIfQamBackpress=1
static double gGuardUs = 0.0;                // --guardUs=

// --- Helpers for SNR/EVM/BER ------------------------------------------------
static inline double EvmFromSnrDb(double snrEsDb) {
  const double snrLin = std::pow(10.0, snrEsDb / 10.0);
  return 1.0 / std::sqrt(snrLin);
}
static inline double SigmaFromEvm(double evm, double Es) {
  return evm * std::sqrt(Es / 2.0);
}
static inline double Qfunc(double x) {
  return 0.5 * std::erfc(x / std::sqrt(2.0));
}
static inline double BerMqam(double snrEbLin, uint32_t M) {
  const double k = (3.0 * std::log2(M)) / ((double)M - 1.0);
  const double a = 4.0 / std::log2(M) * (1.0 - 1.0 / std::sqrt((double)M));
  return a * Qfunc(std::sqrt(k * snrEbLin));
}

// ==================== ARP CACHE POPULATION ====================
// Function to populate ARP cache of all nodes in ns-3, prevents ARP blocking in Wi-Fi networks
// Execute after assigning IP addresses
// Author: inspired by Pavel Boyko snippet
void PopulateARPcache() {
  Ptr<ArpCache> arp = CreateObject<ArpCache>();
  arp->SetAliveTimeout(Seconds(3600 * 24 * 365));

  // Pierwsza pętla: tworzymy wpisy ARP
  for (NodeList::Iterator i = NodeList::Begin(); i != NodeList::End(); ++i) {
    Ptr<Ipv4L3Protocol> ip = (*i)->GetObject<Ipv4L3Protocol>();
    NS_ASSERT(ip);  // zamiast ip != 0

    ObjectVectorValue interfaces;
    ip->GetAttribute("InterfaceList", interfaces);

    for (ObjectVectorValue::Iterator j = interfaces.Begin();
         j != interfaces.End(); ++j) {
      Ptr<Ipv4Interface> ipIface = (*j).second->GetObject<Ipv4Interface>();
      NS_ASSERT(ipIface); // zamiast != 0

      Ptr<NetDevice> device = ipIface->GetDevice();
      NS_ASSERT(device);  // zamiast != 0

      Mac48Address addr = Mac48Address::ConvertFrom(device->GetAddress());

      for (uint32_t k = 0; k < ipIface->GetNAddresses(); k++) {
        Ipv4Address ipAddr = ipIface->GetAddress(k).GetLocal();
        if (ipAddr == Ipv4Address::GetLoopback()) {
          continue;
        }

        ArpCache::Entry *entry = arp->Add(ipAddr);
        Ipv4Header ipv4Hdr;
        ipv4Hdr.SetDestination(ipAddr);
        Ptr<Packet> p = Create<Packet>(100);
        entry->MarkWaitReply(ArpCache::Ipv4PayloadHeaderPair(p, ipv4Hdr));
        entry->MarkAlive(addr);
      }
    }
  }

  // Druga pętla: podpinamy cache do interfejsów
  for (NodeList::Iterator i = NodeList::Begin(); i != NodeList::End(); ++i) {
    Ptr<Ipv4L3Protocol> ip = (*i)->GetObject<Ipv4L3Protocol>();
    NS_ASSERT(ip);  // zamiast != 0

    ObjectVectorValue interfaces;
    ip->GetAttribute("InterfaceList", interfaces);

    for (ObjectVectorValue::Iterator j = interfaces.Begin();
         j != interfaces.End(); ++j) {
      Ptr<Ipv4Interface> ipIface = (*j).second->GetObject<Ipv4Interface>();
      NS_ASSERT(ipIface);  // zamiast != 0
      ipIface->SetAttribute("ArpCache", PointerValue(arp));
    }
  }
}


// =========================== TXOP CONFIG ===========================
static const uint32_t kAggScale = 3;     // --aggScale= bajty na jednostkę wartości symbolu
static const uint32_t kAggHdrBytes = 8;  // stały nagłówek APP (timestamp 8B)
// AC selection is configurable to avoid unrequested inter-AC contention.

struct AcCfg {
  uint8_t tid;
  Time txop;
  std::string edcaPath;
  uint8_t dscp;
};
static AcCfg kAcVoice{6, MicroSeconds(1504), "VO_EdcaTxopN", 0xC0}; // EF
static AcCfg kAcVideo{5, MicroSeconds(3008), "VI_EdcaTxopN", 0x88}; // AF41

static const uint16_t kBgPort = 8000; // legacy single-flow (pozostało tylko w definicji)
static const uint16_t kCovertPortVO = 9001;
static const uint16_t kCovertPortVI = 9002;

// =========================== QAM CONFIG ============================
static uint32_t kQamDataSize = 2000; // usuwamy const, sterowane --qamPktB=
static const uint16_t kQamPort = 9009;
static const double kQamEs = 10.0;
static std::string kQamSecretMsg = "";

// ============================ HELPERS ==============================
static std::vector<uint8_t> BitsFromString(const std::string &s) {
  std::vector<uint8_t> b;
  b.reserve(8 * s.size());
  for (unsigned char c : s)
    for (int i = 7; i >= 0; --i)
      b.push_back((c >> i) & 1u);
  return b;
}
static inline void AppendBitsFromValue(std::vector<uint8_t> &out, uint32_t value, uint32_t nbits) {
  for (int i = (int)nbits - 1; i >= 0; --i)
    out.push_back((value >> i) & 1u);
}

// Airtime estimator (us) for a single 802.11 data frame of payloadBytes
static double AirTimeUsForPayload(uint32_t payloadBytes) {
  const double bits = 8.0 * (payloadBytes + gMacHdrBytes);
  const double txUs = (bits / (gAirMbps * 1e6)) * 1e6; // b / (b/s) -> s -> us
  return gPlcpUs + txUs + gSifsUs + gAckUs + gDifsUs + gAvgBackoffUs;
}

static std::string PseudoRandomString(size_t len, uint64_t seed,
                                      const std::string &alphabet =
                                          "abcdefghijklmnopqrstuvwxyz"
                                          "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                          "0123456789"
                                          "_-;,':.!?/()[]{}|~@#$%^&*+=") {
  std::mt19937_64 gen(seed);
  std::uniform_int_distribution<size_t> dist(0, alphabet.size() - 1);
  std::string s;
  s.reserve(len);
  for (size_t i = 0; i < len; ++i)
    s.push_back(alphabet[dist(gen)]);
  return s;
}

// =========================== TXOP (CH#1) ===========================

struct Symbol {
  uint32_t value;                   // raw (plaintext) value, kept for reference
  const AcCfg *ac;
  uint32_t bitsCarried;
  std::vector<uint8_t> plainBits;   // the nbits plaintext covert bits of this symbol
};

static std::vector<Symbol> PackBitsToSymbols(const std::vector<uint8_t> &bits) {
  std::vector<Symbol> out;
  size_t i = 0;
  uint32_t idx = 0;
  while (i < bits.size()) {
    bool useVi = (gCovertAc == "VI") || (gCovertAc == "BOTH" && (idx % 2 == 1));
    uint32_t nbits = useVi ? 11u : 10u;
    uint32_t val = 0;
    std::vector<uint8_t> pb;
    for (uint32_t b = 0; b < nbits; ++b) {
      uint8_t bit = (i < bits.size()) ? (bits[i++] & 1u) : 0u;
      val = (val << 1) | bit;
      pb.push_back(bit);
    }
    out.push_back(Symbol{val, useVi ? &kAcVideo : &kAcVoice, nbits, std::move(pb)});
    ++idx;
  }
  return out;
}

// Covert codec and per-AC MAC sequence counters (stand-in for 802.11 SN).
static stego::MacCovertCodec *gMacCodec = nullptr;
static uint32_t gSnVo = 0, gSnVi = 0;

class CovertTxApp : public Application {
public:
  void Setup(Ptr<NetDevice> dev, Ptr<WifiNetDevice> wifiDev, Ipv4Address apAddr) {
    m_dev = dev;
    m_wifi = wifiDev;
    m_apAddr = apAddr;
  }
  void LoadSymbols(const std::vector<Symbol> &symbols) { m_symbols = symbols; }
  bool HasSymbols() const { return !m_symbols.empty(); }

  // moreData: current More Data value for this TXOP (sets duration semantics).
  void SendNextSymbol(bool moreData) {
    if (!HasSymbols())
      return;
    m_lastAirtimeUs = 0.0;
    const Symbol &s = m_symbols[m_symIdx];
    m_symIdx = (m_symIdx + 1) % m_symbols.size();
    const AcCfg &ac = *s.ac;
    const bool isVo = (ac.tid == kAcVoice.tid);
    Ptr<Socket> sock = isVo ? m_sockVO : m_sockVI;
    stego::Ac sac = isVo ? stego::Ac::Voice : stego::Ac::Video;

    m_lastNominalTxopUs = ac.txop.GetMicroSeconds();

    // Encrypt (per-frame) + whiten with the MAC sequence number of this frame.
    uint32_t &sn = isVo ? gSnVo : gSnVi;
    stego::MacCovertCodec::Encoded enc = gMacCodec->Encode(s.plainBits, sn, sac);
    const uint32_t durUs = enc.durUs;           // truncation microsecond (covert)
    const uint32_t xWhit = enc.symbol;          // encrypted symbol value

    // Transport: carry (ts, whitened symbol, SN, AC) so the receiver recovers
    // the symbol exactly; payload size approximates the covert TXOP duration so
    // the modelled airtime matches the encoded truncation point.
    const uint32_t approxBytes = (uint32_t)std::max<double>(
        0.0, ((durUs - gPlcpUs - gSifsUs - gAckUs) * gAirMbps) / 8.0);
    const uint32_t wireBytes = std::max<uint32_t>(kAggHdrBytes + 9, approxBytes);
    std::vector<uint8_t> wire(wireBytes, 0);
    uint64_t tsUs = (uint64_t)Simulator::Now().GetMicroSeconds();
    std::memcpy(wire.data(), &tsUs, sizeof(tsUs));
    std::memcpy(wire.data() + 8, &xWhit, 4);
    std::memcpy(wire.data() + 12, &sn, 4);
    wire[16] = isVo ? 0 : 1;

    Ptr<Packet> p = Create<Packet>(wire.data(), wire.size());
    sock->Send(p);
    m_lastAirtimeUs += AirTimeUsForPayload(wireBytes);

    // Per-TXOP observation row (what a warden can measure).
    if (gTxopCsv.is_open() && Simulator::Now().GetSeconds() >= gWarmupSeconds &&
        Simulator::Now().GetSeconds() < gWarmupSeconds + gSimSeconds)
      gTxopCsv << Simulator::Now().GetMicroSeconds() << ","
               << (isVo ? "VO" : "VI") << "," << sn << ","
               << (moreData ? 1 : 0) << "," << gTxMode << ","
               << durUs << "\n";

    sn = (sn + 1) & 0x0FFF;   // 802.11 SN is 12-bit
  }

  double LastSentAirtimeUs() const { return m_lastAirtimeUs; }
  double LastNominalTxopUs() const { return m_lastNominalTxopUs; }

private:
  Ptr<NetDevice> m_dev;
  Ptr<WifiNetDevice> m_wifi;
  Ipv4Address m_apAddr;
  std::vector<Symbol> m_symbols;
  uint32_t m_symIdx = 0;
  Ptr<Socket> m_sockVO, m_sockVI;
  mutable double m_lastAirtimeUs = 0.0;
  mutable double m_lastNominalTxopUs = 0.0;

  void StartApplication() override {
    m_sockVO = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_sockVO->SetIpTos(kAcVoice.dscp);
    m_sockVO->SetPriority(kAcVoice.tid);
    m_sockVO->Connect(InetSocketAddress(m_apAddr, kCovertPortVO));

    m_sockVI = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_sockVI->SetIpTos(kAcVideo.dscp);
    m_sockVI->SetPriority(kAcVideo.tid);
    m_sockVI->Connect(InetSocketAddress(m_apAddr, kCovertPortVI));
  }
};

class CovertRxApp : public Application {
public:
  void Setup(Ptr<WifiNetDevice> wifiDev) { m_wifi = wifiDev; }
  const std::vector<uint8_t> &GetRxBits() const { return m_rxBits; }

  struct Stats {
    uint64_t bitsDecoded = 0;
    double seconds = 0.0;
    uint64_t delaySamples = 0;
    double avgDelayUs = 0.0;
    double jitterUs = 0.0;
    uint64_t voPkts = 0;
    uint64_t viPkts = 0;
  };
  Stats GetStats() const {
    Stats s;
    s.bitsDecoded = m_bitsDecoded;
    s.seconds = m_haveWindow ? (m_lastRx.GetSeconds() - m_firstRx.GetSeconds()) : 0.0;
    s.delaySamples = m_delaySamples;
    s.avgDelayUs = (m_delaySamples ? m_delaySumUs / (double)m_delaySamples : 0.0);
    s.jitterUs = m_jitterUs;
    s.voPkts = m_voPkts;
    s.viPkts = m_viPkts;
    return s;
  }

private:
  Ptr<WifiNetDevice> m_wifi;
  Ptr<Socket> m_sockVO, m_sockVI;
  std::vector<uint8_t> m_rxBits;
  bool m_haveWindow = false;
  Time m_firstRx, m_lastRx;
  uint64_t m_bitsDecoded = 0;

  // delay/jitter metrics (RFC3550 jitter estimator)
  uint64_t m_delaySamples = 0;
  double m_delaySumUs = 0.0;
  double m_jitterUs = 0.0;
  bool m_hasPrevTransit = false;
  double m_prevTransitUs = 0.0;

  // NEW: RX counters per AC
  uint64_t m_voPkts = 0, m_viPkts = 0;

  void StartApplication() override {
    m_sockVO = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_sockVO->Bind(InetSocketAddress(Ipv4Address::GetAny(), kCovertPortVO));
    m_sockVO->SetRecvCallback(MakeCallback(&CovertRxApp::OnRxVO, this));

    m_sockVI = Socket::CreateSocket(GetNode(), UdpSocketFactory::GetTypeId());
    m_sockVI->Bind(InetSocketAddress(Ipv4Address::GetAny(), kCovertPortVI));
    m_sockVI->SetRecvCallback(MakeCallback(&CovertRxApp::OnRxVI, this));
  }

  void OnRxVO(Ptr<Socket> sock) {
    ++m_voPkts;
    OnRxCommon(sock, 6);
  }
  void OnRxVI(Ptr<Socket> sock) {
    ++m_viPkts;
    OnRxCommon(sock, 5);
  }

  void OnRxCommon(Ptr<Socket> sock, uint8_t tid) {
    Address from;
    Ptr<Packet> p;
    while ((p = sock->RecvFrom(from))) {
      if (!m_haveWindow) {
        m_haveWindow = true;
        m_firstRx = Simulator::Now();
      }
      m_lastRx = Simulator::Now();

      // timestamp + opóźnienia
      if (p->GetSize() >= kAggHdrBytes) {
        uint8_t hdr[kAggHdrBytes];
        p->CopyData(hdr, kAggHdrBytes);
        uint64_t tsUs = 0;
        std::memcpy(&tsUs, hdr, sizeof(tsUs));
        double transitUs = (double)(Simulator::Now().GetMicroSeconds() - tsUs);
        m_delaySumUs += transitUs;
        ++m_delaySamples;
        if (m_hasPrevTransit) {
          double d = std::fabs(transitUs - m_prevTransitUs);
          m_jitterUs += (d - m_jitterUs) / 16.0;
        } else {
          m_hasPrevTransit = true;
        }
        m_prevTransitUs = transitUs;
      }

      // 1 packet = 1 TXOP symbol: recover the whitened symbol value and SN from
      // the header, then decrypt. (The whitened TXOP duration that a warden
      // observes is logged separately on the TX side to txop_trace.csv.)
      const uint32_t nbits = (tid == 6) ? 10u : 11u;
      stego::Ac sac = (tid == 6) ? stego::Ac::Voice : stego::Ac::Video;
      if (p->GetSize() >= 17) {
        uint8_t hb[17];
        p->CopyData(hb, 17);
        uint32_t xWhit = 0, sn = 0;
        std::memcpy(&xWhit, hb + 8, 4);
        std::memcpy(&sn, hb + 12, 4);
        std::vector<uint8_t> bits = gMacCodec->DecodeSymbol(xWhit, sn, sac);
        for (uint8_t b : bits) m_rxBits.push_back(b);
        m_bitsDecoded += nbits;
      }
    }
  }
};

// ========================= QAM-16 STEGO (CH#2, analytical) ===================

struct QamCtx {
  std::mt19937_64 gen{SEED};
  std::uniform_int_distribution<int> randByte{0, 255};
  std::deque<uint32_t> inflight;
  uint32_t inflightLimit = gInflightLimit;

  bool haveWindow = false;
  Time firstRx, lastRx;

  uint64_t totalPackets = 0, errorPackets = 0;
  uint64_t totalBits = 0, errorBits = 0;
  uint64_t overtBitsOk = 0;

  uint64_t hiddenBitsAttempted = 0;
  uint64_t hiddenBitsDetected = 0;
  uint64_t hiddenBitsErrors = 0;

  uint32_t nextSeq = 1;

  uint64_t delaySamples = 0;
  double delaySumUs = 0.0;
  double jitterUs = 0.0;
  bool hasPrevTransit = false;
  double prevTransitUs = 0.0;
};

class QamApp : public Application {
public:
  void Setup(Ptr<Node> txNode, Ptr<Node> rxNode, Ipv4Address rxAddr, uint16_t port) {
    m_txNode = txNode;
    m_rxNode = rxNode;
    m_rxAddr = rxAddr;
    m_port = port;
  }
  void Init() {
    TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
    m_recv = Socket::CreateSocket(m_rxNode, tid);
    m_recv->Bind(InetSocketAddress(Ipv4Address::GetAny(), m_port));
    m_recv->SetRecvCallback(MakeCallback(&QamApp::OnRecv, this));
    m_send = Socket::CreateSocket(m_txNode, tid);
  }

  // Zwraca przewidywany airtime pakietu (na potrzeby statystyk),
  // ale pacing jest teraz związany z gQamTargetBps w HybridController.
  double SendOnePacketIfPossible() {
    if (m_q.inflight.size() >= m_q.inflightLimit)
      return 0.0;

    const uint32_t headerBytes = 12; // 4B seq + 8B ts
    NS_ASSERT_MSG(kQamDataSize > headerBytes, "kQamDataSize must be > 12");

    std::vector<uint8_t> raw(kQamDataSize - headerBytes);
    for (uint32_t i = 0; i < raw.size(); ++i)
      raw[i] = (uint8_t)m_q.randByte(m_q.gen);

    uint32_t seq = m_q.nextSeq++;
    uint64_t tsUs = (uint64_t)Simulator::Now().GetMicroSeconds();

    std::vector<uint8_t> wire(headerBytes + raw.size());
    wire[0] = (seq >> 24) & 0xFF;
    wire[1] = (seq >> 16) & 0xFF;
    wire[2] = (seq >> 8) & 0xFF;
    wire[3] = seq & 0xFF;
    std::memcpy(&wire[4], &tsUs, 8);
    std::copy(raw.begin(), raw.end(), wire.begin() + headerBytes);

    Ptr<Packet> pkt = Create<Packet>(wire.data(), wire.size());
    m_send->SendTo(pkt, 0, InetSocketAddress(m_rxAddr, m_port));

    ++m_q.totalPackets;
    m_pktStore[seq] = std::move(raw);
    m_q.inflight.push_back(seq);

    return AirTimeUsForPayload(kQamDataSize);
  }

  const QamCtx &GetCtx() const { return m_q; }

private:
  Ptr<Node> m_txNode, m_rxNode;
  Ipv4Address m_rxAddr;
  uint16_t m_port{kQamPort};
  Ptr<Socket> m_send, m_recv;
  QamCtx m_q;
  std::unordered_map<uint32_t, std::vector<uint8_t>> m_pktStore;

  void StartApplication() override {
    Init();
    const uint32_t bitsPerPkt = 8u * kQamDataSize;
    const uint32_t M = 16;
    const double L = std::log2((double)M);
    const double snrEsLin = std::pow(10.0, kSnrEsDb / 10.0);
    const double snrEbLin = snrEsLin / L;
    double pb = BerMqam(snrEbLin, M);
    pb = std::clamp(pb, 1e-12, 0.49);
    m_binomOvert = std::binomial_distribution<uint32_t>(bitsPerPkt, pb);
    m_pbOvert = pb;
    m_pbHidden = std::min(0.49, m_pbOvert * gHiddenBerRatio());
  }

  double gHiddenBerRatio() const { return gHiddenBerScale; }

  void OnRecv(Ptr<Socket> sock) {
    Address from;
    Ptr<Packet> pkt = sock->RecvFrom(from);

    if (!m_q.haveWindow) {
      m_q.haveWindow = true;
      m_q.firstRx = Simulator::Now();
    }
    m_q.lastRx = Simulator::Now();

    std::vector<uint8_t> buf(pkt->GetSize());
    pkt->CopyData(buf.data(), buf.size());
    if (buf.size() < 12)
      return;

    uint32_t seq = (uint32_t(buf[0]) << 24) | (uint32_t(buf[1]) << 16) |
                   (uint32_t(buf[2]) << 8) | uint32_t(buf[3]);
    uint64_t tsUs = 0;
    std::memcpy(&tsUs, buf.data() + 4, 8);

    auto it = m_pktStore.find(seq);
    if (it == m_pktStore.end())
      return;

    if (!m_q.inflight.empty() && m_q.inflight.front() == seq)
      m_q.inflight.pop_front();

    const std::vector<uint8_t> &ref = it->second;
    const uint32_t bits = 8u * (uint32_t)ref.size();
    m_q.totalBits += bits;

    double transitUs = (double)(Simulator::Now().GetMicroSeconds() - tsUs);
    m_q.delaySumUs += transitUs;
    ++m_q.delaySamples;
    if (m_q.hasPrevTransit) {
      double d = std::fabs(transitUs - m_q.prevTransitUs);
      m_q.jitterUs += (d - m_q.jitterUs) / 16.0;
    } else {
      m_q.hasPrevTransit = true;
    }
    m_q.prevTransitUs = transitUs;

    uint32_t errBits = m_binomOvert(m_q.gen);
    m_q.errorBits += errBits;
    m_q.overtBitsOk += (bits - errBits);
    if (errBits > 0)
      ++m_q.errorPackets;

    const uint32_t symPerPkt = (uint32_t)ref.size() * 2u;
    const uint32_t hiddenCandidates =
        (uint32_t)std::llround(symPerPkt * gStegoQuadrantHit);
    const uint32_t hiddenAttempt =
        2u * (uint32_t)std::llround(hiddenCandidates * gStegoDetectProb);
    m_q.hiddenBitsAttempted += hiddenAttempt;
    if (hiddenAttempt > 0) {
      std::binomial_distribution<uint32_t> binomHidden(hiddenAttempt, m_pbHidden);
      uint32_t herr = binomHidden(m_q.gen);
      m_q.hiddenBitsErrors += herr;
      m_q.hiddenBitsDetected += (hiddenAttempt - herr);
    }

    m_pktStore.erase(it);
  }

  std::binomial_distribution<uint32_t> m_binomOvert{0, 0.0};
  double m_pbOvert = 0.0;
  double m_pbHidden = 0.0;
};

// ====================== CONTROLLER (pattern-driven, airtime-paced) ===========

class HybridController : public Application {
public:
  void Setup(Ptr<CovertTxApp> txopTx, Ptr<QamApp> qamApp) {
    m_txopTx = txopTx;
    m_qam = qamApp;
  }
  void SetPattern(const std::string &pat) { m_pattern = pat.empty() ? "0" : pat; }
  void StartController() {
    Simulator::Schedule(Seconds(1.0), &HybridController::NextStep, this);
  }

  struct CStats {
    uint64_t steps = 0, ones = 0, zeros = 0, txopSends = 0;
    double sumDtUs = 0.0;
    uint64_t nZero = 0, nOne = 0;
    double sumZeroDt = 0.0, sumOneDt = 0.0;
    double sumQamUs = 0.0, sumTxopUs = 0.0;
  };

  CStats GetStats() const { return m_stats; }
  std::string GetPatternHead(uint32_t n = 64) const {
    if (m_pattern.size() <= n)
      return m_pattern;
    return m_pattern.substr(0, n);
  }

private:
  Ptr<CovertTxApp> m_txopTx;
  Ptr<QamApp> m_qam;
  std::string m_pattern{"0"};
  uint32_t m_patIdx = 0;

  CStats m_stats;
  std::mt19937 m_rng{SEED ^ 0xD1CEu};
  std::uniform_real_distribution<double> m_md{0.0, 1.0};

  void StartApplication() override {}

  // Transmission mode decides whether a TXOP (MAC) symbol is emitted this step:
  //   Only-PHY   : never (More Data = 0)
  //   Full-Usage : always (More Data = 1)
  //   Adaptive   : only when the (modelled) More Data bit is 1
  void NextStep() {
    ++m_stats.steps;

    bool moreData;
    bool emitTxop;
    if (gTxMode == 0) {            // Only-PHY
      moreData = false; emitTxop = false;
    } else if (gTxMode == 1) {     // TXOP Full-Usage
      moreData = true;  emitTxop = true;
    } else {                       // Adaptive
      moreData = (m_md(m_rng) < gMoreDataProb);
      emitTxop = moreData;
    }
    const char mode = emitTxop ? '1' : '0';

    // Pure reference mode: do not create millions of 1-us empty events.
    if (gTxMode == 0 && gQamTargetBps <= 0.0) return;

    // 1) QAM: wysyłamy co krok, jeśli gQamTargetBps > 0.
    // Zwracamy airtime ramki, ale pacing oparty jest na gQamTargetBps.
    double qamAirtimeUs = 0.0;
    bool qamSent = false;
    if (gQamTargetBps > 0.0) {
      qamAirtimeUs = m_qam->SendOnePacketIfPossible(); // 0.0 jeśli inflight pełny
      qamSent = (qamAirtimeUs > 0.0);
    }

    // 2) TXOP (opcjonalnie)
    double txopUsActual = 0.0;
    double txopUsNominal = 0.0;
    const bool qamBackpress = (gQamTargetBps > 0.0 && !qamSent);
    bool didTxop = false;

    if (mode == '1' && m_txopTx->HasSymbols()) {
      ++m_stats.ones;
      if (!(gPauseTxopIfQamBackpress && qamBackpress)) {
        m_txopTx->SendNextSymbol(moreData);
        txopUsActual = m_txopTx->LastSentAirtimeUs();
        txopUsNominal = m_txopTx->LastNominalTxopUs();
        didTxop = true;
        ++m_stats.txopSends;
      }
    } else {
      ++m_stats.zeros;
    }

    // 3) Efektywny czas zajęcia medium przez TXOP = co najmniej nominalny TXOP
    double txopUsEffective =
        didTxop ? std::max(txopUsActual, txopUsNominal) : 0.0;

    // 4) Pacing QAM po gQamTargetBps: idealny odstęp czasowy między pakietami QAM
    double qamIdealUs = 0.0;
    if (gQamTargetBps > 0.0) {
      // czas potrzebny na wysłanie kQamDataSize bajtów przy gQamTargetBps [bps]
      qamIdealUs = ((double)kQamDataSize * 8.0 / gQamTargetBps) * 1e6;
    }

    // Jeśli QAM jest wyłączony (0Mbps) i nie ma TXOP, unikamy dtUs=0
    double dtUs = qamIdealUs + txopUsEffective + gGuardUs;
    if (!didTxop && dtUs < gIdleStepUs)
      dtUs = gIdleStepUs; // deterministic idle pacing, no 1-us busy loop
    if (dtUs < 1.0) dtUs = 1.0;

    // Statystyki: sumujemy airtime QAM (rzeczywisty) i efektywny TXOP
    m_stats.sumDtUs += dtUs;
    m_stats.sumQamUs += qamAirtimeUs;
    m_stats.sumTxopUs += txopUsEffective;
    if (mode == '1') {
      ++m_stats.nOne;
      m_stats.sumOneDt += dtUs;
    } else {
      ++m_stats.nZero;
      m_stats.sumZeroDt += dtUs;
    }

    Simulator::Schedule(MicroSeconds((uint64_t)std::llround(dtUs)),
                        &HybridController::NextStep, this);
  }
};

// =============================== MAIN ========================================

int main(int argc, char **argv) {
  SEED = 2214; // deterministic by default; change with --seed

  bool enablePcap = false;

  CommandLine cmd;
  uint32_t secretLen = 64; // --secretLen=
  uint32_t txMsgLen = 256; // --txMsgLen=
  uint64_t seedSecret =
      SEED ^ 0x9E3779B97F4A7C15ULL; // --seedSecret=
  uint64_t seedTxMsg =
      SEED ^ 0xBF58476D1CE4E5B9ULL; // --seedTxMsg=

  cmd.AddValue("qamPktB",
               "Bytes per QAM packet (incl. 12B header)", kQamDataSize);
  cmd.AddValue("secretLen", "Length of pseudorandom QAM secret message",
               secretLen);
  cmd.AddValue("txMsgLen", "Length of pseudorandom TXOP source string",
               txMsgLen);
  cmd.AddValue("seedSecret", "PRNG seed for QAM secret", seedSecret);
  cmd.AddValue("seedTxMsg", "PRNG seed for TXOP text->bits", seedTxMsg);
  cmd.AddValue("pcap", "Enable PCAP", enablePcap);
  cmd.AddValue("seed", "Fixed ns-3 and model PRNG seed", SEED);
  cmd.AddValue("run", "ns-3 RNG run number", gRun);
  cmd.AddValue("covertAc", "AC of covert packets: VO, VI, BOTH", gCovertAc);
  cmd.AddValue("idleStepUs", "Adaptive step spacing when no covert packet is sent [us]", gIdleStepUs);

  cmd.AddValue("macControl", "Use real EDCA MAC time budgets instead of UDP covert symbols", gMacControl);
  cmd.AddValue("macBudgetCsv", "Chosen per-real-TXOP budgets", gMacBudgetCsvPath);
  cmd.AddValue("mode", "Tx mode: 0=Only-PHY, 1=TXOP Full-Usage, 2=Adaptive", gTxMode);
  cmd.AddValue("crypt", "Covert encryption: 0=off, 1=ARX, 2=TTAK", gCrypt);
  cmd.AddValue("mdProb", "Adaptive mode: modelled More Data probability", gMoreDataProb);
  cmd.AddValue("txopCsv", "Per-TXOP observation CSV (for detectors)", gTxopCsvPath);
  cmd.AddValue("snrDb", "QAM Es/N0 in dB (analytical BER)", kSnrEsDb);
  cmd.AddValue("sim", "Measurement time after warmup (seconds)", gSimSeconds);
   cmd.AddValue("warmup", "Measurement warmup in seconds", gWarmupSeconds);
   cmd.AddValue("macTxopCsv", "Actual MAC EDCA TXOP trace path", gMacTxopCsvPath);
   cmd.AddValue("satAc", "Additional saturated UDP on covert STA: NONE, VO, VI, BOTH", gSatAc);
   cmd.AddValue("satRate", "Offered rate per saturated AC", gSatRate);
   cmd.AddValue("satPacketB", "Payload size of saturation packets", gSatPacketBytes);

  cmd.AddValue("airMbps", "Effective PHY payload rate (Mb/s)", gAirMbps);
  cmd.AddValue("macHdrB", "MAC hdr+FCS bytes added to payload", gMacHdrBytes);
  cmd.AddValue("plcpUs", "PLCP/preamble time [us]", gPlcpUs);
  cmd.AddValue("ackUs", "ACK frame time [us]", gAckUs);
  cmd.AddValue("bkoffUs", "Average backoff [us]", gAvgBackoffUs);

  cmd.AddValue("aggScale", "TXOP bytes scale per symbol value",
               (uint32_t &)kAggScale);
  cmd.AddValue("inflight", "Max in-flight QAM packets", gInflightLimit);
  cmd.AddValue("gateHit", "Hidden: quadrant hit probability",
               gStegoQuadrantHit);
  cmd.AddValue("gateDetect", "Hidden: detection (geometry) probability",
               gStegoDetectProb);
  cmd.AddValue("hiddenBerScale", "Hidden BER multiplier vs overt BER",
               gHiddenBerScale);

  cmd.AddValue("stations",
               "Number of extra background STAs generating ordinary traffic",
               gNumBgSta);
  cmd.AddValue("bgRate", "Per-station background rate (e.g., 8Mbps)", gBgRate);
  cmd.AddValue("bgPktB", "Per-station background packet size (bytes)",
               gBgPktBytes);

  cmd.AddValue("legBgRate",
               "Main QAM offered IP rate (e.g., 5Mbps, 0Mbps to disable)",
               gLegacyBgRate);
  cmd.AddValue("legBgPktB",
               "Legacy background packet size (kept only for CSV metadata)",
               gLegacyBgPktBytes);

  cmd.AddValue("csv", "CSV output filepath", gCsvPath);

  // NEW pacing switches
  cmd.AddValue("pauseTxopIfQamBackpress",
               "Pause TXOP if QAM couldn't send in this step (default=1)",
               gPauseTxopIfQamBackpress);
  cmd.AddValue("guardUs",
               "Guard time [us] added after (QAM+TXOP) airtime (default=50)",
               gGuardUs);

  cmd.Parse(argc, argv);
  RngSeedManager::SetSeed(SEED);
  RngSeedManager::SetRun(gRun);
  NS_ABORT_MSG_IF(gCovertAc != "VO" && gCovertAc != "VI" && gCovertAc != "BOTH",
                  "covertAc must be VO, VI or BOTH");
  NS_ABORT_MSG_IF(gTxMode > 2, "mode must be 0, 1 or 2");
  NS_ABORT_MSG_IF(gMoreDataProb < 0.0 || gMoreDataProb > 1.0, "mdProb must be in [0,1]");
  NS_ABORT_MSG_IF(gIdleStepUs < 1.0, "idleStepUs must be >= 1");
  // When --seed changes, derive payload PRNG seeds from the selected seed unless
  // explicitly set by the user in --seedSecret / --seedTxMsg.
  // Those values are declared before command-line parsing for backward compatibility.
   NS_ABORT_MSG_IF(gSatAc != "NONE" && gSatAc != "VO" && gSatAc != "VI" && gSatAc != "BOTH",
                   "satAc must be NONE, VO, VI, or BOTH");
   NS_ABORT_MSG_IF(gWarmupSeconds < 2.0, "warmup must be >= 2 s (controller starts at ~1.9s)");
   NS_ABORT_MSG_IF(gSatPacketBytes < 17, "satPacketB must be at least 17");

  if (seedSecret == (2214ULL ^ 0x9E3779B97F4A7C15ULL))
      seedSecret = static_cast<uint64_t>(SEED) ^ 0x9E3779B97F4A7C15ULL;
  if (seedTxMsg == (2214ULL ^ 0xBF58476D1CE4E5B9ULL))
      seedTxMsg = static_cast<uint64_t>(SEED) ^ 0xBF58476D1CE4E5B9ULL;
  // Covert codec (per-frame encryption + SeqNum whitening). SCF/DF/BCF/MAC/key
  // are a fixed context here; the real header values are used in the trace-sink
  // (real-frame) variant.
  stego::FrameParams baseParams;
  baseParams.df = 0x002C; baseParams.bcf = 0x2A;
  baseParams.mac = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};
  for (int i = 0; i < 16; ++i) baseParams.key[i] = (uint8_t)(0x10 * (i + 1));
  static stego::MacCovertCodec macCodec(baseParams, (int)gCrypt);
  gMacCodec = &macCodec;

  gTxopCsv.open(gTxopCsvPath.c_str());
  if (gTxopCsv.is_open())
    gTxopCsv << "t_us,ac,seqnum,more_data,mode,txop_dur_us\n";
   gMacBudgetCsv.open(gMacBudgetCsvPath.c_str());
   NS_ABORT_MSG_IF(!gMacBudgetCsv.is_open(), "Cannot open budget CSV");
   gMacBudgetCsv << "ac,start_s,target_budget_us,link_id,active\n";
   gMacTxopCsv.open(gMacTxopCsvPath.c_str());
   NS_ABORT_MSG_IF(!gMacTxopCsv.is_open(), "Cannot open MAC TXOP CSV");
   gMacTxopCsv << "variant,ac,start_s,end_s,link_id,limit_us,used_us,unused_us,over_limit\n";

  // Przeliczamy docelową przepływność QAM z legBgRate
  // (0Mbps => brak wysyłania QAM)
  try {
    DataRate qamDr(gLegacyBgRate);
    gQamTargetBps = qamDr.GetBitRate();
  } catch (...) {
    std::cerr << "[WARN] Cannot parse legBgRate=\"" << gLegacyBgRate
              << "\", falling back to 0 bps\n";
    gQamTargetBps = 0.0;
  }
  NS_ABORT_MSG_IF(gMacControl && gQamTargetBps > 0.0,
                  "macControl=1 requires --legBgRate=0Mbps (QAM app controller disabled)");

  kQamSecretMsg = PseudoRandomString(
      secretLen, seedSecret,
      "abcdefghijklmnopqrstuvwxyz"
      "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
      "0123456789_-");
  const std::string txSrc = PseudoRandomString(txMsgLen, seedTxMsg);
  std::vector<uint8_t> txBits = BitsFromString(txSrc);

  // ----------------- Nodes -----------------
  NodeContainer apNode;
  apNode.Create(1);
  NodeContainer covertSta;
  covertSta.Create(1);
  NodeContainer bgStas;
  bgStas.Create(gNumBgSta);

  // Mobility
  MobilityHelper mob;
  mob.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  mob.Install(apNode);
  mob.Install(covertSta);
  mob.Install(bgStas);
  apNode.Get(0)->GetObject<MobilityModel>()->SetPosition(
      Vector(0.0, 0.0, 0.0));
  covertSta.Get(0)->GetObject<MobilityModel>()->SetPosition(
      Vector(5.0, 0.0, 0.0));
  for (uint32_t i = 0; i < gNumBgSta; i++) {
    bgStas.Get(i)->GetObject<MobilityModel>()->SetPosition(
        Vector(4.0 + 0.5 * i, 1.0 * (i % 3), 0.0));
  }

  // Internet
  InternetStackHelper internet;
  internet.Install(apNode);
  internet.Install(covertSta);
  internet.Install(bgStas);

  // Channel + PHY
  YansWifiChannelHelper chan;
  chan.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
  chan.AddPropagationLoss("ns3::LogDistancePropagationLossModel");
  YansWifiPhyHelper phy;
  phy.SetChannel(chan.Create());
  phy.Set("TxPowerStart", DoubleValue(30.0));
  phy.Set("TxPowerEnd", DoubleValue(30.0));
  phy.Set("TxPowerLevels", UintegerValue(1));
  phy.Set("Antennas", UintegerValue(1));
  phy.Set("ChannelSettings",
          StringValue("{1, 20, BAND_2_4GHZ, 0}")); // 802.11ax, MCS3

  Config::SetDefault("ns3::WifiMac::QosSupported", BooleanValue(true));
  WifiHelper wifi;
  wifi.SetStandard(WIFI_STANDARD_80211ax);
  wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager", "DataMode",
                               StringValue("HeMcs3"), "ControlMode",
                               StringValue("HeMcs0"));

  WifiMacHelper mac;
  Ssid ssid = Ssid("hybrid-ssid");

  // AP
  mac.SetType("ns3::ApWifiMac", "Ssid", SsidValue(ssid));
   mac.SetEdca(AC_VO, "TxopLimits", AttributeContainerValue<TimeValue>(std::vector<Time>{MicroSeconds(1504)}));
   mac.SetEdca(AC_VI, "TxopLimits", AttributeContainerValue<TimeValue>(std::vector<Time>{MicroSeconds(3008)}));
  NetDeviceContainer apDev = wifi.Install(phy, mac, apNode.Get(0));

  // Covert STA
  mac.SetType("ns3::StaWifiMac", "Ssid", SsidValue(ssid), "ActiveProbing",
              BooleanValue(false));
  mac.SetEdca(AC_VO, "TxopLimits", AttributeContainerValue<TimeValue>(std::vector<Time>{MicroSeconds(1504)}));
  mac.SetEdca(AC_VI, "TxopLimits", AttributeContainerValue<TimeValue>(std::vector<Time>{MicroSeconds(3008)}));
  NetDeviceContainer staDev = wifi.Install(phy, mac, covertSta.Get(0));

  // Background STAs
  NetDeviceContainer bgStaDevs;
  for (uint32_t i = 0; i < gNumBgSta; i++) {
    NetDeviceContainer one = wifi.Install(phy, mac, bgStas.Get(i));
    bgStaDevs.Add(one);
  }

  // PHY timing
  Config::Set("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/Slot",
              TimeValue(MicroSeconds(gSlotUs)));
  Config::Set("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/Sifs",
              TimeValue(MicroSeconds(gSifsUs)));

  // Addressing
  NetDeviceContainer allWifiDevices;
  allWifiDevices.Add(staDev);
  allWifiDevices.Add(apDev);
  allWifiDevices.Add(bgStaDevs);
  Ipv4AddressHelper ipv4;
  ipv4.SetBase("10.0.0.0", "255.255.255.0");
  Ipv4InterfaceContainer ifaces = ipv4.Assign(allWifiDevices);
  Ipv4Address apAddr = ifaces.GetAddress(1);
  Ipv4Address covertAddr = ifaces.GetAddress(0);

  // ARP CACHE POPULATION (ważne!)
  PopulateARPcache();

  Ptr<WifiNetDevice> txWifi = DynamicCast<WifiNetDevice>(staDev.Get(0));
  Ptr<WifiNetDevice> rxWifi = DynamicCast<WifiNetDevice>(apDev.Get(0));

   // Same ns-3.44 QosTxop::TxopTrace as used by the working Legacy experiment.
   Ptr<WifiMac> sourceMac = txWifi->GetMac();
   Ptr<QosTxop> voTxop = sourceMac->GetQosTxop(AC_VO);
   Ptr<QosTxop> viTxop = sourceMac->GetQosTxop(AC_VI);
   NS_ABORT_MSG_IF(!voTxop || !viTxop, "QoS TXOP unavailable");
   voTxop->TraceConnectWithoutContext("TxopTrace", MakeBoundCallback(&RecordMacTxop, std::string("VO"), 1504.0));
   viTxop->TraceConnectWithoutContext("TxopTrace", MakeBoundCallback(&RecordMacTxop, std::string("VI"), 3008.0));

   // MAC-based mode: select a real budget at each EDCA TXOP grant.
   // The codec is fed with the same input plaintext symbols as the old app,
   // but only the MAC budget is transmitted, not additional UDP covert packets.
   if (gMacControl) {
     std::vector<Time> voBudgets, viBudgets;
     uint32_t localVoSn = 0, localViSn = 0;
     for (const auto& symbol : PackBitsToSymbols(txBits)) {
       bool isVo = (symbol.ac->tid == kAcVoice.tid);
       uint32_t& sn = isVo ? localVoSn : localViSn;
       auto enc = gMacCodec->Encode(symbol.plainBits, sn, isVo ? stego::Ac::Voice : stego::Ac::Video);
       // Clamp a requested budget to a feasible positive EDCA time limit.
       Time maxBudget = isVo ? kAcVoice.txop : kAcVideo.txop;
       Time budget = std::min(maxBudget, MicroSeconds(std::max<uint32_t>(200, enc.durUs)));
       (isVo ? voBudgets : viBudgets).push_back(budget);
       sn = (sn + 1) & 0x0FFF;
     }
     const double probability = gTxMode == 1 ? 1.0 : (gTxMode == 2 ? gMoreDataProb : 0.0);
     if (gCovertAc == "VO" || gCovertAc == "BOTH") {
       voTxop->ConfigureCovertTxop(voBudgets, probability, 30001);
     }
     if (gCovertAc == "VI" || gCovertAc == "BOTH") {
       viTxop->ConfigureCovertTxop(viBudgets, probability, 30002);
     }
     voTxop->TraceConnectWithoutContext("CovertBudgetTrace", MakeBoundCallback(&RecordMacBudget, std::string("VO")));
     viTxop->TraceConnectWithoutContext("CovertBudgetTrace", MakeBoundCallback(&RecordMacBudget, std::string("VI")));
   }

   // Optional saturation source on the SAME STA as the covert application.
   // Warning: this adds ordinary MAC frames; trace measures aggregate STA AC behavior.
   auto addSaturation = [&](uint16_t port, uint8_t tos) {
     PacketSinkHelper sink("ns3::UdpSocketFactory",
                           InetSocketAddress(Ipv4Address::GetAny(), port));
     ApplicationContainer receivers = sink.Install(apNode.Get(0));
     receivers.Start(Seconds(0.0));
     receivers.Stop(Seconds(gWarmupSeconds + gSimSeconds));
     OnOffHelper onoff("ns3::UdpSocketFactory", InetSocketAddress(apAddr, port));
     onoff.SetConstantRate(DataRate(gSatRate), gSatPacketBytes);
     onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
     onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
     onoff.SetAttribute("Tos", UintegerValue(tos));
     ApplicationContainer senders = onoff.Install(covertSta.Get(0));
     senders.Start(Seconds(0.5));
     senders.Stop(Seconds(gWarmupSeconds + gSimSeconds));
   };
   if (gSatAc == "VO" || gSatAc == "BOTH") addSaturation(19001, 0xC0);
   if (gSatAc == "VI" || gSatAc == "BOTH") addSaturation(19002, 0x88);

  // NEW: Background contention — K stations sending ordinary UDP (BE) to AP
  for (uint32_t i = 0; i < gNumBgSta; i++) {
    uint16_t port = kBgBasePort + i;
    PacketSinkHelper sink("ns3::UdpSocketFactory",
                          InetSocketAddress(Ipv4Address::GetAny(), port));
    ApplicationContainer sapps = sink.Install(apNode.Get(0));
    sapps.Start(Seconds(0.05 + 0.001 * i));

    OnOffHelper onoff("ns3::UdpSocketFactory",
                      InetSocketAddress(apAddr, port));
    onoff.SetConstantRate(DataRate(gBgRate), gBgPktBytes);
    onoff.SetAttribute("OnTime",
                       StringValue("ns3::ConstantRandomVariable[Constant=1]"));
    onoff.SetAttribute("OffTime",
                       StringValue("ns3::ConstantRandomVariable[Constant=0]"));
    ApplicationContainer oapps = onoff.Install(bgStas.Get(i));
    oapps.Start(Seconds(0.10 + 0.002 * i));
  }

  // TXOP channel (infinite queue)
  std::vector<Symbol> symbols = PackBitsToSymbols(txBits);
  Ptr<CovertTxApp> txopTx = CreateObject<CovertTxApp>();
  txopTx->Setup(staDev.Get(0), txWifi, apAddr);
  txopTx->LoadSymbols(symbols);
  covertSta.Get(0)->AddApplication(txopTx);
  txopTx->SetStartTime(Seconds(0.5));

  Ptr<CovertRxApp> txopRx = CreateObject<CovertRxApp>();
  txopRx->Setup(rxWifi);
  apNode.Get(0)->AddApplication(txopRx);
  txopRx->SetStartTime(Seconds(0.5));

  // QAM channel (analytical) — AP -> STA ukryta (dst: covertAddr)
  Ptr<QamApp> qam = CreateObject<QamApp>();
  qam->Setup(apNode.Get(0), covertSta.Get(0), covertAddr, kQamPort);
  apNode.Get(0)->AddApplication(qam);
  qam->SetStartTime(Seconds(0.5));

  // Controller (pattern-driven, airtime-paced)
  Ptr<HybridController> ctrl = CreateObject<HybridController>();
  ctrl->Setup(txopTx, qam);
  ctrl->SetPattern("1"); // pattern no longer used; mode drives emission
  covertSta.Get(0)->AddApplication(ctrl);
  ctrl->SetStartTime(Seconds(0.9));
  // In MAC mode no synthetic UDP symbols and no application pacing.
  // Offered traffic is generated by OnOff, and QosTxop selects budgets per real TXOP.
  if (!gMacControl) ctrl->StartController();

  // PCAP (optional)
  if (enablePcap) {
    YansWifiPhyHelper phyPcap;
    phyPcap.SetPcapDataLinkType(WifiPhyHelper::DLT_IEEE802_11_RADIO);
    NetDeviceContainer toDump;
    toDump.Add(staDev);
    toDump.Add(apDev);
    toDump.Add(bgStaDevs);
    phyPcap.EnablePcap("hybrid-cc", toDump, true);
  }

  // === FlowMonitor: instalacja ===
  FlowMonitorHelper flowmonHelper;
  Ptr<FlowMonitor> monitor = flowmonHelper.InstallAll();

  // Run
  Simulator::Stop(Seconds(gWarmupSeconds + gSimSeconds));
  Simulator::Run();

  // REPORT
  auto stats = txopRx->GetStats();
  std::vector<uint8_t> rxBits = txopRx->GetRxBits();
  const size_t txLen = txBits.size();
  const size_t rxLen = rxBits.size();
  const size_t L = std::min(txLen, rxLen);
  uint64_t errorsCommon = 0;
  for (size_t i = 0; i < L; ++i)
    if (txBits[i] != rxBits[i])
      ++errorsCommon;
  const double berCommon = (L > 0) ? double(errorsCommon) / double(L) : 0.0;

  const double secondsTxop = stats.seconds;
  const uint64_t bitsDecoded = stats.bitsDecoded;
  const double bpsTxop =
      (secondsTxop > 0.0) ? (double(bitsDecoded) / secondsTxop) : 0.0;

  const auto &qc = qam->GetCtx();
  double per =
      (qc.totalPackets ? double(qc.errorPackets) / qc.totalPackets : 0.0);
  double ber =
      (qc.totalBits ? double(qc.errorBits) / qc.totalBits : 0.0);
  double qamSeconds =
      (qc.haveWindow ? (qc.lastRx - qc.firstRx).GetSeconds() : 0.0);
  double overtPhyBps = (qc.totalBits > 0 && qamSeconds > 0.0)
                           ? (double)qc.overtBitsOk / qamSeconds
                           : 0.0;
  double grossPhyBpsTx = (qc.totalBits > 0 && qamSeconds > 0.0)
                             ? (double)qc.totalBits / qamSeconds
                             : 0.0;
  double hiddenGoodput =
      (qc.hiddenBitsDetected > 0 && qamSeconds > 0.0)
          ? (double)qc.hiddenBitsDetected / qamSeconds
          : 0.0;
  double hiddenBer =
      (qc.hiddenBitsDetected + qc.hiddenBitsErrors) > 0
          ? (double)qc.hiddenBitsErrors /
                (double)(qc.hiddenBitsDetected + qc.hiddenBitsErrors)
          : 0.0;

  const double evmReport = EvmFromSnrDb(kSnrEsDb);
  const double sigmaUsed = SigmaFromEvm(evmReport, kQamEs);

  // Delay/jitter (ms)
  double txopAvgDelayMs =
      (stats.delaySamples ? (stats.avgDelayUs / 1000.0) : 0.0);
  double txopJitterMs = stats.jitterUs / 1000.0;
  double qamAvgDelayMs =
      (qc.delaySamples ? (qc.delaySumUs / (double)qc.delaySamples) / 1000.0
                       : 0.0);
  double qamJitterMs = qc.jitterUs / 1000.0;

  // Controller stats
  auto cst = ctrl->GetStats();

  const char *modeName = gTxMode == 0 ? "Only-PHY"
                       : gTxMode == 1 ? "TXOP Full-Usage" : "Adaptive";
  std::cout << "\n=== HYBRID REPORT (mode-driven, analytical QAM) ===\n";
  std::cout << "[NOTE] Measured MAC TXOP != encoded durUs. Both traces are separate.\n";
  std::cout << "[NOTE] MAC control=" << gMacControl
            << "; adaptive selection uses probability, not actual MoreData bit.\n";
  std::cout << "Tx mode: " << gTxMode << " (" << modeName << "), crypt="
            << (gCrypt == 0 ? "off" : gCrypt == 1 ? "ARX" : "TTAK")
            << ", mdProb=" << gMoreDataProb << "\n";
  std::cout << "Simulation time: " << gSimSeconds
            << " s; QAM target rate: " << gLegacyBgRate
            << "; Stations(tlo)=" << gNumBgSta << ", bgRate=" << gBgRate
            << ", bgPktB=" << gBgPktBytes << "\n";
  std::cout << "Pacing: guardUs=" << gGuardUs
            << ", pauseTxopIfQamBackpress="
            << (gPauseTxopIfQamBackpress ? "1" : "0") << "\n";
  std::cout << "[CTRL] steps=" << cst.steps << " ones=" << cst.ones
            << " zeros=" << cst.zeros << " txopSends=" << cst.txopSends
            << " avg_dt=" << std::fixed << std::setprecision(2)
            << (cst.steps ? cst.sumDtUs / cst.steps : 0.0) << " us"
            << " avg_qamUs="
            << (cst.steps ? cst.sumQamUs / cst.steps : 0.0) << " us"
            << " avg_txopUs="
            << (cst.steps ? cst.sumTxopUs / cst.steps : 0.0) << " us"
            << " avg_dt_ones="
            << (cst.nOne ? cst.sumOneDt / cst.nOne : 0.0) << " us"
            << " avg_dt_zeros="
            << (cst.nZero ? cst.sumZeroDt / cst.nZero : 0.0) << " us"
            << "\n";

  std::cout << "\n-- TXOP channel --\n";
  std::cout << "Decoded bits: " << bitsDecoded << "\n";
  std::cout << std::fixed << std::setprecision(6)
            << "Measurement window: " << secondsTxop << " s\n";
  std::cout << std::setprecision(2)
            << "Goodput: " << bpsTxop << " bps (" << bpsTxop / 1000.0
            << " kbps, " << bpsTxop / 1e6 << " Mbps)\n";
  std::cout << std::setprecision(4)
            << "BER_common: " << (berCommon * 100.0) << " %\n";
  std::cout << std::setprecision(2)
            << "Avg one-way delay: " << txopAvgDelayMs
            << " ms, jitter: " << txopJitterMs << " ms"
            << " [VO=" << stats.voPkts << ", VI=" << stats.viPkts
            << ", total=" << (stats.voPkts + stats.viPkts) << "]\n";

  std::cout << "\nQAM noise model: SNR_Es = " << std::setprecision(2)
            << kSnrEsDb << " dB, EVM = " << std::setprecision(4)
            << evmReport << " (" << std::setprecision(2)
            << evmReport * 100.0 << " %)"
            << ", sigma = " << std::setprecision(4) << sigmaUsed << "\n";

  std::cout << "\n-- QAM-16 overt (analytical BER) --\n";
  std::cout << "Packets: " << qc.totalPackets
            << ", ErrPkts: " << qc.errorPackets
            << " -> PER ~= " << std::setprecision(6) << per << "\n";
  std::cout << "Bits: " << qc.totalBits
            << ", ErrBits: " << qc.errorBits
            << " -> BER ~= " << std::setprecision(6) << ber << "\n";
  std::cout << std::setprecision(2)
            << "Overt PHY goodput: " << overtPhyBps << " bps ("
            << overtPhyBps / 1000.0 << " kbps, " << overtPhyBps / 1e6
            << " Mbps)\n"
            << "Gross PHY rate TX: " << grossPhyBpsTx << " bps ("
            << grossPhyBpsTx / 1000.0 << " kbps, "
            << grossPhyBpsTx / 1e6 << " Mbps)\n";

  std::cout << "\n-- QAM-16 hidden (model) --\n";
  std::cout << "Hidden bits attempted: " << qc.hiddenBitsAttempted
            << ", detected: " << qc.hiddenBitsDetected
            << ", errors: " << qc.hiddenBitsErrors
            << " -> BER_hidden ~= " << std::setprecision(6)
            << hiddenBer << "\n";
  std::cout << std::setprecision(2)
            << "Hidden goodput: " << hiddenGoodput << " bps ("
            << hiddenGoodput / 1000.0 << " kbps, "
            << hiddenGoodput / 1e6 << " Mbps)\n";

  std::cout << "\n-- QAM delay/jitter --\n";
  std::cout << std::setprecision(2)
            << "Avg one-way delay: " << qamAvgDelayMs
            << " ms, jitter: " << qamJitterMs << " ms"
            << " [" << qc.delaySamples << " pkts]\n";

  std::cout << "\n-- Airtime model (tunable) --\n";
  std::cout << "airMbps=" << gAirMbps << ", plcpUs=" << gPlcpUs
            << ", ackUs=" << gAckUs << ", difs=" << gDifsUs
            << ", bkoff=" << gAvgBackoffUs
            << ", macHdrB=" << gMacHdrBytes << "\n";

  // ======================= FLOWMONITOR: odczyt metryk IP ======================
  monitor->CheckForLostPackets();
  double offeredIpBps = 0.0;
  double rxIpBps = 0.0;
  double ipLoss = 0.0;
  double ipDelayMs = 0.0;
  double ipJitterMs = 0.0;

  Ptr<Ipv4FlowClassifier> classifier =
      DynamicCast<Ipv4FlowClassifier>(flowmonHelper.GetClassifier());
  auto flowStats = monitor->GetFlowStats();

  for (const auto &kv : flowStats) {
    const FlowMonitor::FlowStats &st = kv.second;
    Ipv4FlowClassifier::FiveTuple t = classifier->FindFlow(kv.first);
    // QAM: AP -> Covert STA (UDP, dst port = kQamPort)
    if (t.protocol != 17)
      continue; // UDP
    if (!(t.sourceAddress == apAddr && t.destinationAddress == covertAddr))
      continue;
    if (t.destinationPort != kQamPort)
      continue;

    double win = gSimSeconds; // symulacja trwa gSimSeconds sekund

    offeredIpBps = (win > 0.0) ? (st.txBytes * 8.0) / win : 0.0;
    rxIpBps = (win > 0.0) ? (st.rxBytes * 8.0) / win : 0.0;

    ipLoss =
        (st.txPackets > 0) ? double(st.lostPackets) / double(st.txPackets)
                           : 0.0;
    ipDelayMs = (st.rxPackets > 0)
                    ? (st.delaySum.GetSeconds() / st.rxPackets) * 1000.0
                    : 0.0;
    ipJitterMs =
        (st.rxPackets > 1)
            ? (st.jitterSum.GetSeconds() / (st.rxPackets - 1)) * 1000.0
            : 0.0;
  }

  std::cout << std::setprecision(2)
            << "\n[FlowMonitor QAM] offered_ip=" << offeredIpBps / 1e6
            << " Mb/s, "
            << "rx_ip=" << rxIpBps / 1e6 << " Mb/s, "
            << "loss=" << (ipLoss * 100.0) << " %, "
            << "delay=" << ipDelayMs << " ms, "
            << "jitter=" << ipJitterMs << " ms\n";

  // ============================ CSV APPEND =============================
  // Kolumny:
  // stations_total,snr_db,frame_bytes,
  // bg_rate,leg_bg_rate,leg_bg_pktB,
  // txop_goodput_bps,txop_delay_ms,txop_jitter_ms,
  // qam_per,qam_ber,qam_goodput_bps,
  // hidden_ber,hidden_goodput_bps,
  // qam_delay_ms,qam_jitter_ms,
  // offered_ip_bps,rx_ip_bps,ip_loss,ip_delay_ms,ip_jitter_ms
  const uint32_t stationsTotal =
      gNumBgSta + 1; // dodatkowe STAs + 1 skryta STA

  // Pełne MPDU: payload (kQamDataSize) + nagłówek MAC/FCS (gMacHdrBytes)
  const uint32_t frameBytes = kQamDataSize + gMacHdrBytes;


  bool csvExists = false;
  {
    std::ifstream fi(gCsvPath.c_str(), std::ios::in);
    csvExists = fi.good();
  }

  {
    std::ofstream fo(gCsvPath.c_str(),
                     std::ios::out | std::ios::app);
    if (!fo) {
      std::cerr << "[CSV] ERROR: cannot open file for append: "
                << gCsvPath << "\n";
    } else {
      if (!csvExists) {
        fo << "stations_total,"
              "snr_db,"
              "frame_bytes,"
              "bg_rate,"
              "leg_bg_rate,"
              "leg_bg_pktB,"
              "txop_goodput_bps,"
              "txop_delay_ms,"
              "txop_jitter_ms,"
              "qam_per,"
              "qam_ber,"
              "qam_goodput_bps,"
              "hidden_ber,"
              "hidden_goodput_bps,"
              "qam_delay_ms,"
              "qam_jitter_ms,"
              "offered_ip_bps,"
              "rx_ip_bps,"
              "ip_loss,"
              "ip_delay_ms,"
              "ip_jitter_ms"
           << "\n";
      }

      fo << std::setprecision(10) << std::fixed << stationsTotal << ","
         << kSnrEsDb << "," << frameBytes << "," << gBgRate << ","
         << gLegacyBgRate << "," << gLegacyBgPktBytes << "," << bpsTxop
         << "," << txopAvgDelayMs << "," << txopJitterMs << "," << per
         << "," << ber << "," << overtPhyBps << "," << hiddenBer << ","
         << hiddenGoodput << "," << qamAvgDelayMs << "," << qamJitterMs
         << "," << offeredIpBps << "," << rxIpBps << "," << ipLoss << ","
         << ipDelayMs << "," << ipJitterMs << "\n";
    }
  }
  // ========================== END CSV APPEND ===========================

  std::cout << "\n[MAC TXOP] VO=" << gMacVoCount << " VI=" << gMacViCount
            << " satAc=" << gSatAc << " covertAc=" << gCovertAc
            << " satRate=" << gSatRate << " seed=" << SEED << " run=" << gRun << "\n";
  if (gMacVoCount) std::cout << "[MAC TXOP] VO mean unused=" << gMacVoUnusedSum / gMacVoCount << " us\n";
  if (gMacViCount) std::cout << "[MAC TXOP] VI mean unused=" << gMacViUnusedSum / gMacViCount << " us\n";
  if (gMacBudgetCsv.is_open()) gMacBudgetCsv.close();
  if (gMacTxopCsv.is_open()) gMacTxopCsv.close();
  if (gTxopCsv.is_open()) gTxopCsv.close();
  Simulator::Destroy();
  return 0;
}
