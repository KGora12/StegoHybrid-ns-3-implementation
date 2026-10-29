// ns-3.44: actual EDCA TXOP measurements for a saturated STA -> AP.
// Put in scratch/legacy_txop_344.cc and run with ./ns3 run 'scratch/legacy_txop_344 --ac=VO'
#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/wifi-module.h"
#include "ns3/mobility-module.h"
#include "ns3/internet-module.h"
#include "ns3/applications-module.h"
#include <fstream>
#include <iostream>
#include <iomanip>
#include <string>
#include <algorithm>
#include <vector>
using namespace ns3;

static std::ofstream out;
static double warmup = 2.0;
static double duration = 300.0;
static uint64_t voCount = 0, viCount = 0;
static double voUnused = 0, viUnused = 0;

static void OnTxop(std::string ac, double limitUs, Time start, Time actual, uint8_t linkId)
{
    const double t = start.GetSeconds();
    if (t < warmup || t >= warmup + duration) return;
    const double used = actual.GetNanoSeconds() / 1000.0;
    const double unused = std::max(0.0, limitUs - used);
    if (ac == "VO") { ++voCount; voUnused += unused; }
    else { ++viCount; viUnused += unused; }
    out << "legacy," << ac << ',' << std::fixed << std::setprecision(3)
        << t << ',' << (t + actual.GetSeconds()) << ','
        << static_cast<unsigned>(linkId) << ',' << limitUs << ','
        << used << ',' << unused << ',' << (used > limitUs ? 1 : 0) << '\n';
}

int main(int argc, char** argv)
{
    std::string ac = "VO";  // VO, VI, BOTH
    std::string csv = "legacy_txop.csv";
    std::string offered = "100Mbps"; // deliberately above usable link throughput
    uint32_t packetSize = 1000;
    uint32_t seed = 1;
    CommandLine cmd(__FILE__);
    cmd.AddValue("ac", "VO, VI or BOTH", ac);
    cmd.AddValue("csv", "Output path", csv);
    cmd.AddValue("sim", "Measurement seconds (after warmup)", duration);
    cmd.AddValue("warmup", "Seconds before measurement", warmup);
    cmd.AddValue("offered", "UDP offered rate PER active AC", offered);
    cmd.AddValue("packetSize", "UDP payload bytes", packetSize);
    cmd.AddValue("seed", "RNG seed", seed);
    cmd.Parse(argc, argv);
    NS_ABORT_MSG_IF(ac != "VO" && ac != "VI" && ac != "BOTH", "ac must be VO, VI or BOTH");
    RngSeedManager::SetSeed(seed);
    out.open(csv);
    NS_ABORT_MSG_IF(!out.is_open(), "Cannot open CSV output");
    out << "variant,ac,start_s,end_s,link_id,limit_us,used_us,unused_us,over_limit\n";

    NodeContainer sta, ap;
    sta.Create(1); ap.Create(1);
    NodeContainer nodes; nodes.Add(sta); nodes.Add(ap);
    MobilityHelper mobility;
    mobility.SetMobilityModel("ns3::ConstantPositionMobilityModel");
    mobility.Install(nodes);
    sta.Get(0)->GetObject<MobilityModel>()->SetPosition(Vector(5,0,0));
    ap.Get(0)->GetObject<MobilityModel>()->SetPosition(Vector(0,0,0));

    YansWifiChannelHelper channel;
    channel.SetPropagationDelay("ns3::ConstantSpeedPropagationDelayModel");
    channel.AddPropagationLoss("ns3::LogDistancePropagationLossModel");
    YansWifiPhyHelper phy;
    phy.SetChannel(channel.Create());
    phy.Set("ChannelSettings", StringValue("{1, 20, BAND_2_4GHZ, 0}"));
    phy.Set("TxPowerStart", DoubleValue(30));
    phy.Set("TxPowerEnd", DoubleValue(30));
    phy.Set("TxPowerLevels", UintegerValue(1));
    phy.Set("Antennas", UintegerValue(1));
    WifiHelper wifi;
    wifi.SetStandard(WIFI_STANDARD_80211ax);
    wifi.SetRemoteStationManager("ns3::ConstantRateWifiManager", "DataMode", StringValue("HeMcs3"),
                                 "ControlMode", StringValue("HeMcs0"));
    WifiMacHelper mac;
    Ssid ssid("txop-legacy-344");
    mac.SetType("ns3::ApWifiMac", "Ssid", SsidValue(ssid));
    mac.SetEdca(AC_VO, "TxopLimits", AttributeContainerValue<TimeValue>(std::vector<Time>{MicroSeconds(1504)}));
    mac.SetEdca(AC_VI, "TxopLimits", AttributeContainerValue<TimeValue>(std::vector<Time>{MicroSeconds(3008)}));
    NetDeviceContainer apDev = wifi.Install(phy, mac, ap);
    mac.SetType("ns3::StaWifiMac", "Ssid", SsidValue(ssid), "ActiveProbing", BooleanValue(false));
    mac.SetEdca(AC_VO, "TxopLimits", AttributeContainerValue<TimeValue>(std::vector<Time>{MicroSeconds(1504)}));
    mac.SetEdca(AC_VI, "TxopLimits", AttributeContainerValue<TimeValue>(std::vector<Time>{MicroSeconds(3008)}));
    NetDeviceContainer staDev = wifi.Install(phy, mac, sta);
    InternetStackHelper internet; internet.Install(nodes);
    Ipv4AddressHelper ip; ip.SetBase("10.3.0.0", "255.255.255.0");
    auto apIf = ip.Assign(apDev);
    ip.Assign(staDev);
    auto txMac = DynamicCast<WifiNetDevice>(staDev.Get(0))->GetMac();
    auto vo = txMac->GetQosTxop(AC_VO);
    auto vi = txMac->GetQosTxop(AC_VI);
    NS_ABORT_MSG_IF(!vo || !vi, "QoS TXOP not available");
    vo->TraceConnectWithoutContext("TxopTrace", MakeBoundCallback(&OnTxop, std::string("VO"), 1504.0));
    vi->TraceConnectWithoutContext("TxopTrace", MakeBoundCallback(&OnTxop, std::string("VI"), 3008.0));

    auto addFlow = [&](uint16_t port, uint8_t tid, uint8_t tos) {
        PacketSinkHelper sink("ns3::UdpSocketFactory", InetSocketAddress(Ipv4Address::GetAny(), port));
        auto rx = sink.Install(ap.Get(0));
        rx.Start(Seconds(0)); rx.Stop(Seconds(warmup + duration));
        // Set both IP DSCP and socket priority to select the intended EDCA class.
        OnOffHelper onoff("ns3::UdpSocketFactory", InetSocketAddress(apIf.GetAddress(0), port));
        onoff.SetConstantRate(DataRate(offered), packetSize);
        onoff.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
        onoff.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
        onoff.SetAttribute("Tos", UintegerValue(tos));
        auto tx = onoff.Install(sta.Get(0));
        tx.Start(Seconds(0.5)); tx.Stop(Seconds(warmup + duration));
    };
    if (ac == "VO" || ac == "BOTH") addFlow(9001, 6, 0xC0);
    if (ac == "VI" || ac == "BOTH") addFlow(9002, 5, 0x88);
    Simulator::Stop(Seconds(warmup + duration));
    Simulator::Run();
    std::cout << "TXOP samples: VO=" << voCount << " VI=" << viCount << '\n';
    if (voCount) std::cout << "VO mean unused: " << voUnused / voCount << " us\n";
    if (viCount) std::cout << "VI mean unused: " << viUnused / viCount << " us\n";
    Simulator::Destroy();
    out.close();
}

