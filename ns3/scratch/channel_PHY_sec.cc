// QAM-16 stego over 802.11ax (HE MCS3, 20 MHz) with EVM-based noise from SNR
// Next-generation Dirty Constellation (elliptical covert regions).
//
// CORRECTIONS vs. the original channel_s1.cc:
//   (1) SNR scaling fixed. Noise is now referenced to the real symbol energy
//       Es of the 16-QAM constellation (Es = 10 for points {+/-1,+/-3}), so
//       --snrDb is the true Es/N0 in dB and matches channel_s2.cc. The old
//       code used sigma = 10^(-snr/20)/sqrt2 in absolute units, which made the
//       effective Es/N0 about 10 dB higher than the --snrDb value.
//   (2) Covert bits are encrypted per frame (packet) with the paper keystream
//       (Algorithm 1 / 2) before being embedded, so the embedded content is
//       whitened. Decoder decrypts with the same per-frame key.
//   (3) Hidden-BER measurement fixed. Each transmitted symbol now carries a
//       ground-truth covert flag and its plaintext bits; hidden BER is measured
//       by per-symbol alignment, and the geometric covert-detector's
//       robustness (missed / false-positive) is reported separately instead of
//       a single flat vector that de-synchronises on one insertion.
//   (4) Optional --dumpAll dumps every RX error vector with a covert flag, for
//       the external steganalysis / detectability script (detectors.py).
//
// Build: copy to scratch/ of an ns-3.44 tree together with stego_crypto.h.

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/applications-module.h"

#include "stego_crypto.h"

#include <vector>
#include <queue>
#include <random>
#include <iostream>
#include <fstream>
#include <cfloat>
#include <cmath>
#include <unordered_map>
#include <deque>
#include <cstdint>
#include <cstring>
#include <sstream>

using namespace ns3;
NS_LOG_COMPONENT_DEFINE("Qam16Stego");

// ----------------- CLI / globals -----------------
static double   gAirMbps       = 26.0;
static uint32_t gMacHdrBytes   = 36;
static double   gPlcpUs        = 120.0;
static double   gSifsUs        = 16.0;
static double   gSlotUs        = 9.0;
static double   gDifsUs        = 34.0;
static double   gAvgBackoffUs  = 13.5;
static double   gAckUs         = 44.0;
static double   gSimSeconds    = 300.0;
static uint32_t gNumBgSta      = 0;

static uint32_t kDataSize      = 2000;
static uint32_t kUdpPort       = 9;
static double   gSnrDb         = 24.0;      // true Es/N0 in dB (fixed semantics)

// ellipse thresholds
static double gEllipseE1 = 1.0 / 300.0;     // inner (decoder): points inside carry no covert info
static double gEllipseE2 = 1.0 / 70.0;      // covert selection threshold
static double gEllipseE3 = 1.0 / 40.0;      // outer boundary of covert ring

static const double kSendIntervalSec = 0.1;

// encryption selection: 0 = off, 1 = ARX (Alg.1), 2 = TTAK (Alg.2)
static uint32_t gCrypt = 1;
static bool     gDumpAll = false;
static uint32_t gSeed = 12345;
static bool gEnableCovert = true;
static double gEmbedProb = 1.0; // probability of attempting embedding at each eligible symbol
static std::mt19937 gEmbedRng(98765); // separate from channel/noise RNG
static std::string gDumpPath = "all_symbols.csv";

// ------------- stego / metrics -------------
std::ofstream csvFile;     // first-packet constellation (kept for compatibility)
std::ofstream dumpFile;    // all symbols, for detectors.py

std::queue<bool> secretBitQueue;

uint64_t totalPackets = 0, errorPackets = 0, totalBits = 0, errorBits = 0;
uint64_t secretBitsSent = 0;

// covert-detector confusion (geometry) and hidden BER (ground-truth aligned)
uint64_t gCovertSent = 0, gCovertDetected = 0, gCovertMissed = 0, gCovertFalse = 0;
uint64_t gHiddenBitErr = 0, gHiddenBitCmp = 0;

std::mt19937 rng(12345);

// fixed per-station crypto context (SCF is taken from the packet seq below)
static stego::FrameParams gBaseParams;

// ====== per-packet TX record ======
struct SymRec { float x, y; bool covert; uint8_t pb1, pb2; }; // plaintext bits
struct TxRecord { std::vector<SymRec> symbols; };
static uint32_t gSeq = 0;
static std::unordered_map<uint32_t, TxRecord> gTxMap;
static std::deque<uint32_t> gSeqOrder;
static size_t gTxMapMax = 20000;

// ----------------- Constellation -----------------
std::pair<int,int> qam16_map[16] = {
  {-3,-3},{-3,-1},{-3, 3},{-3, 1},{-1,-3},{-1,-1},{-1, 3},{-1, 1},
  { 3,-3},{ 3,-1},{ 3, 3},{ 3, 1},{ 1,-3},{ 1,-1},{ 1, 3},{ 1, 1}
};

uint8_t SecretBitsFromConstellation(int x0, int y0) {
  if ((x0 > 0) && (y0 > 0)) return 0b00;
  if ((x0 < 0) && (y0 > 0)) return 0b01;
  if ((x0 < 0) && (y0 < 0)) return 0b11;
  if ((x0 > 0) && (y0 < 0)) return 0b10;
  return 0xFF;
}

// symbol energy of the constellation (Es = 10 for {+/-1,+/-3})
static double ConstellationEs() {
  double s = 0.0;
  for (auto& p : qam16_map) s += double(p.first*p.first + p.second*p.second);
  return s / 16.0;
}

// ----------- ellipse value (matches Eq. ellipse_covert, rotated per quadrant) ----
float EllipseValue(float x, float y, int x0, int y0) {
  float e = 0.0f;
  if (x0 == -3 && y0 == -3)      e = ((-x + y)    *(-x + y)   )/40.0f + ((x + y + 6)  *(x + y + 6) )/80.0f;
  else if (x0 == -3 && y0 == -1) e = ((-x + y -2) *(-x + y -2))/40.0f + ((x + y + 4)  *(x + y + 4) )/80.0f;
  else if (x0 == -3 && y0 ==  3) e = ((-x - y)    *(-x - y)   )/40.0f + ((x - y + 6)  *(x - y + 6) )/80.0f;
  else if (x0 == -3 && y0 ==  1) e = ((-x - y -2) *(-x - y -2))/40.0f + ((x - y + 4)  *(x - y + 4) )/80.0f;
  else if (x0 == -1 && y0 == -3) e = ((-x + y +2) *(-x + y +2))/40.0f + ((x + y + 4)  *(x + y + 4) )/80.0f;
  else if (x0 == -1 && y0 == -1) e = ((-x + y)    *(-x + y)   )/40.0f + ((x + y + 2)  *(x + y + 2) )/80.0f;
  else if (x0 == -1 && y0 ==  3) e = ((-x - y +2) *(-x - y +2))/40.0f + ((x - y + 4)  *(x - y + 4) )/80.0f;
  else if (x0 == -1 && y0 ==  1) e = ((-x - y)    *(-x - y)   )/40.0f + ((x - y + 2)  *(x - y + 2) )/80.0f;
  else if (x0 ==  3 && y0 == -3) e = ((x + y)     *(x + y)    )/40.0f + ((-x + y + 6) *(-x + y + 6))/80.0f;
  else if (x0 ==  3 && y0 == -1) e = ((x + y -2)  *(x + y -2) )/40.0f + ((-x + y + 4) *(-x + y + 4))/80.0f;
  else if (x0 ==  3 && y0 ==  3) e = ((-x + y)    *(-x + y)   )/40.0f + ((x + y - 6)  *(x + y - 6) )/80.0f;
  else if (x0 ==  3 && y0 ==  1) e = ((-x + 2 + y)*(-x + 2 + y))/40.0f + ((x + y - 4) *(x + y - 4))/80.0f;
  else if (x0 ==  1 && y0 == -3) e = ((x + y + 2) *(x + y + 2))/40.0f + ((-x + y + 4) *(-x + y + 4))/80.0f;
  else if (x0 ==  1 && y0 == -1) e = ((x + y)     *(x + y)    )/40.0f + ((-x + y + 2) *(-x + y + 2))/80.0f;
  else if (x0 ==  1 && y0 ==  3) e = ((-x + y -2) *(-x + y -2))/40.0f + ((x + y - 4)  *(x + y - 4) )/80.0f;
  else if (x0 ==  1 && y0 ==  1) e = ((-x + y)    *(-x + y)   )/40.0f + ((x + y - 2)  *(x + y - 2) )/80.0f;
  else e = 1e9f;
  return e;
}
bool IsPointOutsideInnerEllipse(float x, float y, int x0, int y0) {
  return EllipseValue(x, y, x0, y0) > gEllipseE1;
}

inline void EnsureSecretBits(size_t need) {
  static std::bernoulli_distribution coin(0.5);
  while (secretBitQueue.size() < need) secretBitQueue.push(coin(rng));
}

// per-frame keystream bit (position p), using selected algorithm
static uint8_t KeystreamBit(uint32_t seq, uint32_t p) {
  if (gCrypt == 0) return 0;
  stego::FrameParams fp = gBaseParams;
  fp.scf = seq;                      // per-packet frame counter (stand-in for SCF)
  const uint32_t byteIdx = p >> 3;
  static thread_local uint32_t cachedSeq = 0xFFFFFFFFu;
  static thread_local int cachedAlg = -1;
  static thread_local std::vector<uint8_t> cache;
  if (cachedSeq != seq || cachedAlg != (int)gCrypt || cache.size() <= byteIdx) {
    size_t n = byteIdx + 8;
    if (gCrypt == 2) { stego::TtakKeystream ks(fp); cache = ks.Generate(n); }
    else             { stego::ArxKeystream ks(fp);  cache = ks.Generate(n); }
    cachedSeq = seq; cachedAlg = (int)gCrypt;
  }
  return (cache[byteIdx] >> (7 - (p & 7))) & 1u;
}

// ------------- modulation + stego (per packet) -------------
std::vector<SymRec> ModulateQam16WithStego(const std::vector<uint8_t>& data,
                                           uint32_t seq, bool logToCsv) {
  std::vector<SymRec> symbols;
  uint32_t covertBitIdx = 0;                 // per-frame keystream position
  for (uint8_t byte : data) {
    for (int shift = 4; shift >= 0; shift -= 4) {
      uint8_t nibble = (byte >> shift) & 0x0F;
      auto [x0, y0] = qam16_map[nibble];
      float x = x0, y = y0;
      bool covert = false; uint8_t pb1 = 0, pb2 = 0;

      uint8_t quadrant = SecretBitsFromConstellation(x0, y0);
      EnsureSecretBits(2);
      bool b1 = secretBitQueue.front(); secretBitQueue.pop();
      bool b2 = secretBitQueue.front(); secretBitQueue.pop();

      // encrypt the two plaintext bits with this frame's keystream
      uint8_t c1 = b1 ^ KeystreamBit(seq, covertBitIdx);
      uint8_t c2 = b2 ^ KeystreamBit(seq, covertBitIdx + 1);
      uint8_t ctbits = (c1 << 1) | c2;

      if (gEnableCovert && ctbits == quadrant &&
          std::generate_canonical<double, 53>(gEmbedRng) < gEmbedProb) {
        std::uniform_real_distribution<float> dx(x0 - 2.0f, x0 + 2.0f);
        std::uniform_real_distribution<float> dy(y0 - 2.0f, y0 + 2.0f);
        for (int tries = 0; tries < 200; ++tries) {
          float tx = dx(rng), ty = dy(rng);
          float e = EllipseValue(tx, ty, x0, y0);
          if (e > gEllipseE2 && e <= gEllipseE3) {   // covert ring
            x = tx; y = ty; covert = true; pb1 = b1; pb2 = b2;
            secretBitsSent += 2;
            covertBitIdx += 2;                        // advance keystream
            break;
          }
        }
        if (!covert) { secretBitQueue.push(b1); secretBitQueue.push(b2); }
      } else {
        secretBitQueue.push(b1); secretBitQueue.push(b2);
      }
      if (logToCsv) csvFile << "sent," << x << "," << y << "\n";
      symbols.push_back(SymRec{x, y, covert, pb1, pb2});
    }
  }
  return symbols;
}

// ------------- TX tick -------------
Ptr<Socket> gSendSock;
Address     gRemote;
static bool gLogFirstPacketTx = true;
static bool gLogFirstPacketRx = true;

static inline void PushTxMap(uint32_t seq, TxRecord&& rec) {
  gTxMap.emplace(seq, std::move(rec));
  gSeqOrder.push_back(seq);
  while (gTxMap.size() > gTxMapMax) {
    uint32_t old = gSeqOrder.front(); gSeqOrder.pop_front(); gTxMap.erase(old);
  }
}

void SendQamPacketOnce() {
  if (kDataSize < 4) kDataSize = 4;
  const uint32_t payloadUserBytes = kDataSize - 4;
  std::uniform_int_distribution<int> byteRnd(0, 255);
  std::vector<uint8_t> rawUser(payloadUserBytes);
  for (auto& b : rawUser) b = (uint8_t)byteRnd(rng);

  uint32_t seq = gSeq++;
  bool logThis = gLogFirstPacketTx; gLogFirstPacketTx = false;
  std::vector<SymRec> symbols = ModulateQam16WithStego(rawUser, seq, logThis);

  std::vector<uint8_t> full(kDataSize);
  std::memcpy(full.data(), &seq, sizeof(seq));
  std::memcpy(full.data() + 4, rawUser.data(), rawUser.size());

  TxRecord rec; rec.symbols = std::move(symbols);
  PushTxMap(seq, std::move(rec));

  Ptr<Packet> pkt = Create<Packet>(full.data(), full.size());
  gSendSock->SendTo(pkt, 0, gRemote);
  ++totalPackets;
}

void TrafficTick() {
  SendQamPacketOnce();
  Simulator::Schedule(Seconds(kSendIntervalSec), &TrafficTick);
}

// ------------- UDP receive -------------
void ReceivePacket(Ptr<Socket> socket) {
  Address from;
  Ptr<Packet> pkt = socket->RecvFrom(from);
  std::vector<uint8_t> rx(pkt->GetSize());
  pkt->CopyData(rx.data(), rx.size());
  if (rx.size() < 4) return;
  uint32_t seq = 0; std::memcpy(&seq, rx.data(), sizeof(seq));

  auto it = gTxMap.find(seq);
  if (it == gTxMap.end()) return;
  const auto& sym = it->second.symbols;

  bool logThis = gLogFirstPacketRx && (seq == 0);

  const double Es    = ConstellationEs();
  const double snr   = std::pow(10.0, gSnrDb / 10.0);
  const double sigma = std::sqrt(Es / (2.0 * snr));   // per-dimension noise std
  std::normal_distribution<double> gauss(0.0, sigma);

  std::vector<bool> bits;
  uint32_t covertOrdinal = 0;    // keystream position among detected covert symbols

  for (const SymRec& s : sym) {
    float x = s.x + (float)gauss(rng);
    float y = s.y + (float)gauss(rng);

    float best = FLT_MAX; int idx = 0;
    for (int j = 0; j < 16; ++j) {
      auto [cx, cy] = qam16_map[j];
      float dx = x - cx, dy = y - cy, d2 = dx*dx + dy*dy;
      if (d2 < best) { best = d2; idx = j; }
    }
    auto [cx, cy] = qam16_map[idx];

    if (logThis) csvFile << "received," << x << "," << y << "\n";
    if (gDumpAll)
      dumpFile << seq << "," << x << "," << y << "," << cx << "," << cy
               << "," << (s.covert ? 1 : 0) << "\n";

    bool inSquare = (x >= cx - 1.0f && x <= cx + 1.0f &&
                     y >= cy - 1.0f && y <= cy + 1.0f);
    bool rxCovert = inSquare && IsPointOutsideInnerEllipse(x, y, cx, cy);

    // ---- covert-detection confusion (geometry vs. ground truth) ----
    if (s.covert)  { ++gCovertSent; if (rxCovert) ++gCovertDetected; else ++gCovertMissed; }
    else if (rxCovert) ++gCovertFalse;

    // ---- hidden BER, aligned on ground-truth covert symbols ----
    if (s.covert) {
      uint8_t q  = SecretBitsFromConstellation(cx, cy);
      uint8_t c1 = (q >> 1) & 1, c2 = q & 1;              // recovered ciphertext bits
      uint8_t r1 = c1 ^ KeystreamBit(seq, covertOrdinal * 2);     // decrypt
      uint8_t r2 = c2 ^ KeystreamBit(seq, covertOrdinal * 2 + 1);
      gHiddenBitCmp += 2;
      if (r1 != s.pb1) ++gHiddenBitErr;
      if (r2 != s.pb2) ++gHiddenBitErr;
      ++covertOrdinal;
    }

    for (int b = 3; b >= 0; --b) bits.push_back((idx >> b) & 1);
  }

  // overt BER
  std::vector<uint8_t> demod;
  for (size_t i = 0; i + 7 < bits.size(); i += 8) {
    uint8_t byte = 0;
    for (int b = 0; b < 8; ++b) byte |= (bits[i + b] << (7 - b));
    demod.push_back(byte);
  }
  const std::vector<uint8_t> txdat(rx.begin() + 4, rx.end());
  totalBits += txdat.size() * 8ULL;
  uint32_t localErr = 0;
  size_t n = std::min(txdat.size(), demod.size());
  for (size_t i = 0; i < n; ++i) {
    uint8_t diff = txdat[i] ^ demod[i];
    for (int b = 0; b < 8; ++b) if (diff & (1u << b)) ++localErr;
  }
  errorBits += localErr;
  if (localErr > 0) ++errorPackets;
  if (logThis) gLogFirstPacketRx = false;
  gTxMap.erase(it);
}

// =================== main ===================
int main(int argc, char** argv) {
  CommandLine cmd(__FILE__);
  cmd.AddValue("snrDb",  "True Es/N0 in dB for EVM-based noise", gSnrDb);
  cmd.AddValue("sim",    "Simulation time (s)", gSimSeconds);
  cmd.AddValue("data",   "UDP payload bytes (incl. 4B seq)", kDataSize);
  cmd.AddValue("bg",     "Number of background STAs", gNumBgSta);
  cmd.AddValue("e1",     "Ellipse e1 (inner, decoder)", gEllipseE1);
  cmd.AddValue("e2",     "Ellipse e2 (covert selection)", gEllipseE2);
  cmd.AddValue("e3",     "Ellipse e3 (outer)", gEllipseE3);
  cmd.AddValue("crypt",  "Covert encryption: 0=off,1=ARX,2=TTAK", gCrypt);
  cmd.AddValue("dumpAll","Dump every RX error vector to CSV", gDumpAll);
   cmd.AddValue("dumpPath", "Path for RX symbol CSV", gDumpPath);
   cmd.AddValue("seed", "Reproducible PRNG seed", gSeed);
   cmd.AddValue("enableCovert", "Enable covert constellation changes", gEnableCovert);
  cmd.AddValue("embedProb", "Bernoulli embedding probability per eligible symbol (0..1)", gEmbedProb);
  cmd.Parse(argc, argv);
  if (gEmbedProb < 0.0 || gEmbedProb > 1.0) { std::cerr << "embedProb must be in [0,1]\n"; return 2; }
  rng.seed(gSeed);
  gEmbedRng.seed(gSeed ^ 0x9e3779b9U);
   RngSeedManager::SetSeed(gSeed);

  // fixed crypto context (DF/BCF/MAC/key); SCF = per-packet seq
  gBaseParams.df = 0x002C; gBaseParams.bcf = 0x2A;
  gBaseParams.mac = {0x02,0x00,0x00,0x00,0x00,0x01};
  for (int i = 0; i < 16; ++i) gBaseParams.key[i] = (uint8_t)(0x10 * (i + 1));

  std::ostringstream folderName;
  folderName << "all_constellation/" << gEllipseE1 << "_" << gEllipseE2 << "_" << gEllipseE3;
  { std::ostringstream c; c << "mkdir -p " << folderName.str(); int r = system(c.str().c_str()); (void)r; }
  std::ostringstream constName;
  constName << folderName.str() << "/all_constellation_" << (int)std::round(gSnrDb) << ".csv";
  csvFile.open(constName.str());
  if (csvFile.is_open()) csvFile << "type,x,y\n";

  if (gDumpAll) { dumpFile.open(gDumpPath); dumpFile << "seq,x,y,cx,cy,covert\n"; }

  // ----------------- Nodes / PHY (unchanged) -----------------
  NodeContainer apNode; apNode.Create(1);
  NodeContainer covertSta; covertSta.Create(1);
  NodeContainer bgStas; bgStas.Create(gNumBgSta);

  MobilityHelper mob; mob.SetMobilityModel("ns3::ConstantPositionMobilityModel");
  mob.Install(apNode); mob.Install(covertSta); mob.Install(bgStas);
  apNode.Get(0)->GetObject<MobilityModel>()->SetPosition(Vector(0,0,0));
  covertSta.Get(0)->GetObject<MobilityModel>()->SetPosition(Vector(5,0,0));
  for (uint32_t i = 0; i < gNumBgSta; i++)
    bgStas.Get(i)->GetObject<MobilityModel>()->SetPosition(Vector(4.0 + 0.5*i, 1.0*(i%3), 0));

  InternetStackHelper internet;
  internet.Install(apNode); internet.Install(covertSta); internet.Install(bgStas);

  YansWifiChannelHelper chan; chan.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
  chan.AddPropagationLoss("ns3::LogDistancePropagationLossModel");
  YansWifiPhyHelper phy; phy.SetChannel(chan.Create());
  phy.Set("TxPowerStart", DoubleValue(30.0));
  phy.Set("TxPowerEnd", DoubleValue(30.0));
  phy.Set("TxPowerLevels", UintegerValue(1));
  phy.Set("Antennas", UintegerValue(1));
  phy.Set("ChannelSettings", StringValue("{1, 20, BAND_2_4GHZ, 0}"));

  Config::SetDefault("ns3::WifiMac::QosSupported", BooleanValue(true));
  WifiHelper wifi; wifi.SetStandard(WIFI_STANDARD_80211ax);
  wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager",
    "DataMode", StringValue("HeMcs3"), "ControlMode", StringValue("HeMcs0"));

  WifiMacHelper mac; Ssid ssid = Ssid("hybrid-ssid");
  mac.SetType("ns3::ApWifiMac", "Ssid", SsidValue(ssid));
  NetDeviceContainer apDev = wifi.Install(phy, mac, apNode.Get(0));
  mac.SetType("ns3::StaWifiMac", "Ssid", SsidValue(ssid), "ActiveProbing", BooleanValue(false));
  NetDeviceContainer staDev = wifi.Install(phy, mac, covertSta.Get(0));
  NetDeviceContainer bgStaDevs;
  for (uint32_t i = 0; i < gNumBgSta; i++) bgStaDevs.Add(wifi.Install(phy, mac, bgStas.Get(i)));

  Config::Set("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/Slot", TimeValue(MicroSeconds(gSlotUs)));
  Config::Set("/NodeList/*/DeviceList/*/$ns3::WifiNetDevice/Phy/Sifs", TimeValue(MicroSeconds(gSifsUs)));

  NetDeviceContainer allDev; allDev.Add(staDev); allDev.Add(apDev); allDev.Add(bgStaDevs);
  Ipv4AddressHelper ipv4; ipv4.SetBase("10.0.0.0", "255.255.255.0");
  Ipv4InterfaceContainer ifaces = ipv4.Assign(allDev);
  Ipv4Address apAddr = ifaces.GetAddress(1);

  TypeId tid = TypeId::LookupByName("ns3::UdpSocketFactory");
  Ptr<Socket> rxSock = Socket::CreateSocket(apNode.Get(0), tid);
  rxSock->Bind(InetSocketAddress(Ipv4Address::GetAny(), kUdpPort));
  rxSock->SetRecvCallback(MakeCallback(&ReceivePacket));
  gSendSock = Socket::CreateSocket(covertSta.Get(0), tid);
  gRemote   = InetSocketAddress(apAddr, kUdpPort);

  Simulator::Schedule(Seconds(2.0), &TrafficTick);
  Simulator::Stop(Seconds(gSimSeconds));
  Simulator::Run();
  Simulator::Destroy();

  // ----------------- results -----------------
  double qamPer = totalPackets ? double(errorPackets)/totalPackets : 0.0;
  double qamBer = totalBits    ? double(errorBits)/totalBits       : 0.0;
  double hiddenBer = gHiddenBitCmp ? double(gHiddenBitErr)/double(gHiddenBitCmp) : 0.0;
  double detRate   = gCovertSent ? double(gCovertDetected)/double(gCovertSent) : 0.0;
  double falseRate = (totalBits/2) ? double(gCovertFalse)/double(totalBits/2)   : 0.0;

  std::cout << "\n=== QAM-16 (next-gen dirty constellation) ===\n";
  std::cout << "Es=" << ConstellationEs() << ", true Es/N0=" << gSnrDb << " dB, crypt="
            << (gCrypt==0?"off":gCrypt==1?"ARX":"TTAK") << "\n";
  std::cout << "Packets " << totalPackets << ", PER=" << qamPer
            << ", overt BER=" << qamBer << "\n";
  std::cout << "Covert bits sent=" << secretBitsSent
            << ", hidden BER (aligned)=" << hiddenBer << "\n";
  std::cout << "Covert-detector: det=" << gCovertDetected << "/" << gCovertSent
            << " (" << detRate << "), missed=" << gCovertMissed
            << ", false-pos=" << gCovertFalse << " (rate " << falseRate << ")\n";

  { // metrics CSV
    bool needHeader = true;
    { std::ifstream c("data_s1.csv"); if (c.good() && c.peek()!=std::ifstream::traits_type::eof()) needHeader=false; }
    std::ofstream f("data_s1.csv", std::ios::app);
    if (needHeader) f << "snr_db,qam_per,qam_ber,hidden_ber,det_rate,false_rate,crypt,e1,e2,e3\n";
    f << gSnrDb << "," << qamPer << "," << qamBer << "," << hiddenBer << ","
      << detRate << "," << falseRate << "," << gCrypt << ","
      << gEllipseE1 << "," << gEllipseE2 << "," << gEllipseE3 << "\n";
  }
  if (csvFile.is_open()) csvFile.close();
  if (dumpFile.is_open()) dumpFile.close();
  return 0;
}

