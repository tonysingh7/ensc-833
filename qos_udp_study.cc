#include "ns3/applications-module.h"
#include "ns3/core-module.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/ipv4-flow-classifier.h"
#include "ns3/ipv4-queue-disc-item.h"
#include "ns3/ipv4-packet-filter.h"
#include "ns3/internet-module.h"
#include "ns3/network-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/traffic-control-module.h"

#include <fstream>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

using namespace ns3;


NS_LOG_COMPONENT_DEFINE("QosUdpStudy");

// Small study driver for comparing a few queueing disciplines under the same UDP workload.
// Also allows for outputting to CSV via FlowMOnitor. 
class DscpBandIpv4PacketFilter : public Ipv4PacketFilter
{
  public:
    static TypeId GetTypeId()
    {
        static TypeId tid =
            TypeId("ns3::DscpBandIpv4PacketFilter")
                .SetParent<Ipv4PacketFilter>()
                .SetGroupName("TrafficControl")
                .AddConstructor<DscpBandIpv4PacketFilter>();
        return tid;
    }

  private:
    bool CheckProtocol(Ptr<QueueDiscItem> item) const override
    {
        return DynamicCast<Ipv4QueueDiscItem>(item) != nullptr;
    }

    int32_t DoClassify(Ptr<QueueDiscItem> item) const override
    {
        Ptr<Ipv4QueueDiscItem> ipv4Item = DynamicCast<Ipv4QueueDiscItem>(item);
        if (!ipv4Item)
        {
            return PacketFilter::PF_NO_MATCH;
        }

        uint8_t dscp = ipv4Item->GetHeader().GetTos() >> 2;

        // This one is just the straightforward 4-band mapping I used for the strict-priority case.
        // Kept it explicit on purpose so it is easy to sanity-check later.
        // Explicit DSCP -> band mapping
        // band 0 = highest priority
        // control: AF42 (36)
        // status: AF43 (38)
        // telemetry: AF41 (34)
        // bulk/background: CS1/default
        if (dscp == 36)
        {
            return 0;
        }
        if (dscp == 38)
        {
            return 1;
        }
        if (dscp == 34)
        {
            return 2;
        }
        return 3;
    }
};


NS_OBJECT_ENSURE_REGISTERED(DscpBandIpv4PacketFilter);

class DscpBand3Ipv4PacketFilter : public Ipv4PacketFilter
{
  public:
    static TypeId GetTypeId()
    {
        static TypeId tid =
            TypeId("ns3::DscpBand3Ipv4PacketFilter")
                .SetParent<Ipv4PacketFilter>()
                .SetGroupName("TrafficControl")
                .AddConstructor<DscpBand3Ipv4PacketFilter>();
        return tid;
    }

  private:
    bool CheckProtocol(Ptr<QueueDiscItem> item) const override
    {
        return DynamicCast<Ipv4QueueDiscItem>(item) != nullptr;
    }

    int32_t DoClassify(Ptr<QueueDiscItem> item) const override
    {
        Ptr<Ipv4QueueDiscItem> ipv4Item = DynamicCast<Ipv4QueueDiscItem>(item);
        if (!ipv4Item)
        {
            return PacketFilter::PF_NO_MATCH;
        }

        uint8_t dscp = ipv4Item->GetHeader().GetTos() >> 2;

        // Same idea as above, but trimmed down to 3 bands to mimic pfifo_fast-style behavior.
        // Not a perfect clone, but close enough for the comparison I wanted to run.
        // 3-band mapping for pfifo_fast-style behavior
        // AF42 -> band 0 (highest)
        // AF43 -> band 1
        // AF41 -> band 2
        // everything else -> band 2
        if (dscp == 36)  // AF42
        {
            return 0;
        }
        if (dscp == 38)  // AF43
        {
            return 1;
        }
        return 2;        // AF41, CS1, background, default
    }
};

NS_OBJECT_ENSURE_REGISTERED(DscpBand3Ipv4PacketFilter);

struct ClassSpec
{
    std::string name;
    uint16_t portBase;
    uint32_t packetBytes;
    double ratePps;
    uint8_t dscpDecimal;
    bool downlink;
};

struct RunConfig
{
    std::string runId = "run001";
    std::string scenario = "baseline";
    std::string scheduler = "fifo";
    bool dscp = false;
    uint32_t followers = 4;
    uint32_t queuePkts = 40;

    double bottleneckMbps = 10.0;
    double accessMbps = 100.0;
    double simTime = 20.0;

    double bgRateMbps = 6.0;
    bool burstyBg = true;
};

static uint8_t
MakeTos(bool dscpEnabled, uint8_t dscpDecimal)
{
    // If DSCP is off, just leave the TOS byte alone and let everything blend together.
    if (!dscpEnabled)
    {
        return 0;
    }
    return static_cast<uint8_t>(dscpDecimal << 2);
}

static std::string
SchedulerLabel(const std::string& key)
{
    if (key == "fifo") return "FifoQueueDisc (FIFO)";
    if (key == "pfifo_fast") return "PfifoFast-style 3-band priority FIFO (RR-family baseline)";
    if (key == "fq_pie") return "FqPieQueueDisc (WFQ-family analog)";
    if (key == "prio") return "PrioQueueDisc 4-band strict priority (PRIO)";
    if (key == "fq_codel") return "FqCoDelQueueDisc (CoDel-family fair queue)";
    return key;
}

static void
InstallRootQdiscOnDevice(Ptr<NetDevice> dev, const std::string& scheduler, uint32_t queuePkts)
{
    TrafficControlHelper tch;
    std::ostringstream maxSize;
    maxSize << queuePkts << "p";

    tch.Uninstall(dev);

    if (scheduler == "fifo")
    {
        tch.SetRootQueueDisc("ns3::FifoQueueDisc", "MaxSize", StringValue(maxSize.str()));
        tch.Install(dev);
    }
    else if (scheduler == "pfifo_fast")
    {
        // Stable pfifo_fast-style implementation:
        // 3-band priority FIFO with explicit DSCP-based packet filter.
        uint16_t handle = tch.SetRootQueueDisc("ns3::PrioQueueDisc",
                                               "Priomap",
                                               StringValue("0 1 2 2 0 1 2 2 0 1 2 2 0 1 2 2"));

        TrafficControlHelper::ClassIdList cids =
            tch.AddQueueDiscClasses(handle, 3, "ns3::QueueDiscClass");

        for (uint32_t i = 0; i < 3; ++i)
        {
            tch.AddChildQueueDisc(handle, cids[i], "ns3::FifoQueueDisc",
                                  "MaxSize", StringValue(maxSize.str()));
        }

        tch.AddPacketFilter(handle, "ns3::DscpBand3Ipv4PacketFilter");
        tch.Install(dev);
    }
    else if (scheduler == "fq_codel")
    {
        tch.SetRootQueueDisc("ns3::FqCoDelQueueDisc", "MaxSize", StringValue(maxSize.str()));
        tch.Install(dev);
    }
    else if (scheduler == "fq_pie")
    {
        tch.SetRootQueueDisc("ns3::FqPieQueueDisc", "MaxSize", StringValue(maxSize.str()));
        tch.Install(dev);
    }
    else if (scheduler == "prio")
    {
        // Strict 4-band priority with explicit DSCP-based packet filter.
        uint16_t handle = tch.SetRootQueueDisc("ns3::PrioQueueDisc",
                                               "Priomap",
                                               StringValue("0 1 2 3 0 1 2 3 0 1 2 3 0 1 2 3"));

        TrafficControlHelper::ClassIdList cids =
            tch.AddQueueDiscClasses(handle, 4, "ns3::QueueDiscClass");

        for (uint32_t i = 0; i < 4; ++i)
        {
            tch.AddChildQueueDisc(handle, cids[i], "ns3::FifoQueueDisc",
                                  "MaxSize", StringValue(maxSize.str()));
        }

        tch.AddPacketFilter(handle, "ns3::DscpBandIpv4PacketFilter");
        tch.Install(dev);
    }
    else
    {
        NS_FATAL_ERROR("Unsupported scheduler: " << scheduler);
    }
}

int
main(int argc, char* argv[])
{
    RunConfig cfg;

    CommandLine cmd(__FILE__);
    cmd.AddValue("runId", "Run identifier", cfg.runId);
    cmd.AddValue("scenario", "Scenario name", cfg.scenario);
    cmd.AddValue("scheduler", "fifo|pfifo_fast|fq_pie|prio|fq_codel", cfg.scheduler);
    cmd.AddValue("dscp", "Enable DSCP marking in IP header", cfg.dscp);
    cmd.AddValue("followers", "Number of followers", cfg.followers);
    cmd.AddValue("queuePkts", "Queue size in packets", cfg.queuePkts);
    cmd.AddValue("bottleneckMbps", "Bottleneck link rate in Mbps", cfg.bottleneckMbps);
    cmd.AddValue("accessMbps", "Access link rate in Mbps", cfg.accessMbps);
    cmd.AddValue("bgRateMbps", "Background offered rate in Mbps", cfg.bgRateMbps);
    cmd.AddValue("simTime", "Simulation time in seconds", cfg.simTime);
    cmd.AddValue("burstyBg", "Use bursty background traffic", cfg.burstyBg);
    cmd.Parse(argc, argv);

    const std::string outFile = "../results/summary.csv";

    // Traffic classes used in the study.
    // Rates/sizes are fixed here so the scheduler itself is doing most of the talking.
    std::vector<ClassSpec> classes = {
        {"control",   9000,  64,   200.0, 36, true},   // AF42 -> high priority band
        {"status",    10000, 96,   100.0, 38, false},  // AF43 -> middle priority band
        {"telemetry", 11000, 512,   50.0, 34, false},  // AF41 -> lower priority band
        {"bulk",      12000, 1400,  20.0,  8, false}   // CS1  -> lowest/filler band
    };

    NodeContainer orchestrator;
    orchestrator.Create(1);

    NodeContainer routerA;
    routerA.Create(1);

    NodeContainer routerB;
    routerB.Create(1);

    NodeContainer followers;
    followers.Create(cfg.followers);

    NodeContainer bgSrc;
    bgSrc.Create(1);

    NodeContainer bgDst;
    bgDst.Create(1);

    NodeContainer bgSrcRev;
    bgSrcRev.Create(1);

    NodeContainer bgDstRev;
    bgDstRev.Create(1);

    InternetStackHelper internet;
    internet.Install(orchestrator);
    internet.Install(routerA);
    internet.Install(routerB);
    internet.Install(followers);
    internet.Install(bgSrc);
    internet.Install(bgDst);
    internet.Install(bgSrcRev);
    internet.Install(bgDstRev);

    PointToPointHelper access;
    access.SetDeviceAttribute("DataRate", StringValue(std::to_string((uint32_t)cfg.accessMbps) + "Mbps"));
    access.SetChannelAttribute("Delay", StringValue("1ms"));
    access.SetQueue("ns3::DropTailQueue<Packet>", "MaxSize", StringValue("1p"));

    PointToPointHelper bottleneck;
    bottleneck.SetDeviceAttribute("DataRate", StringValue(std::to_string(cfg.bottleneckMbps) + "Mbps"));
    bottleneck.SetChannelAttribute("Delay", StringValue("5ms"));
    bottleneck.SetQueue("ns3::DropTailQueue<Packet>", "MaxSize", StringValue("1p"));

    NetDeviceContainer devOrchA = access.Install(orchestrator.Get(0), routerA.Get(0));
    NetDeviceContainer devBgSrcA = access.Install(bgSrc.Get(0), routerA.Get(0));
    NetDeviceContainer devAB = bottleneck.Install(routerA.Get(0), routerB.Get(0));

    std::vector<NetDeviceContainer> followerLinks;
    followerLinks.reserve(cfg.followers);
    for (uint32_t i = 0; i < cfg.followers; ++i)
    {
        followerLinks.push_back(access.Install(routerB.Get(0), followers.Get(i)));
    }
    NetDeviceContainer devBgDstB = access.Install(routerB.Get(0), bgDst.Get(0));

    NetDeviceContainer devBgSrcB = access.Install(routerB.Get(0), bgSrcRev.Get(0));
    NetDeviceContainer devBgDstA = access.Install(routerA.Get(0), bgDstRev.Get(0));

    Ipv4AddressHelper ipv4;

    ipv4.SetBase("10.0.0.0", "255.255.255.0");
    Ipv4InterfaceContainer ifOrchA = ipv4.Assign(devOrchA);

    ipv4.SetBase("10.1.0.0", "255.255.255.0");
    Ipv4InterfaceContainer ifBgSrcA = ipv4.Assign(devBgSrcA);

    ipv4.SetBase("10.2.0.0", "255.255.255.0");
    Ipv4InterfaceContainer ifAB = ipv4.Assign(devAB);

    std::vector<Ipv4InterfaceContainer> ifFollowerLinks;
    for (uint32_t i = 0; i < cfg.followers; ++i)
    {
        std::ostringstream subnet;
        subnet << "10.3." << i << ".0";
        ipv4.SetBase(subnet.str().c_str(), "255.255.255.0");
        ifFollowerLinks.push_back(ipv4.Assign(followerLinks[i]));
    }

    ipv4.SetBase("10.4.0.0", "255.255.255.0");
    Ipv4InterfaceContainer ifBgDstB = ipv4.Assign(devBgDstB);

    ipv4.SetBase("10.5.0.0", "255.255.255.0");
    Ipv4InterfaceContainer ifBgSrcB = ipv4.Assign(devBgSrcB);

    ipv4.SetBase("10.6.0.0", "255.255.255.0");
    Ipv4InterfaceContainer ifBgDstA = ipv4.Assign(devBgDstA);

    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    // Install qdisc on both directions of the actual bottleneck.
    InstallRootQdiscOnDevice(devAB.Get(0), cfg.scheduler, cfg.queuePkts);
    InstallRootQdiscOnDevice(devAB.Get(1), cfg.scheduler, cfg.queuePkts);

    const uint16_t bgPort = 13000;
    const uint16_t bgPortRev = 13001;

    ApplicationContainer sinks;
    ApplicationContainer apps;

    for (const auto& cls : classes)
    {
        for (uint32_t i = 0; i < cfg.followers; ++i)
        {
            uint16_t port = cls.portBase + i;

            if (cls.downlink)
            {
                PacketSinkHelper sink("ns3::UdpSocketFactory",
                                      InetSocketAddress(Ipv4Address::GetAny(), port));
                sinks.Add(sink.Install(followers.Get(i)));

                OnOffHelper src("ns3::UdpSocketFactory",
                                InetSocketAddress(ifFollowerLinks[i].GetAddress(1), port));
                src.SetAttribute("PacketSize", UintegerValue(cls.packetBytes));
                src.SetAttribute("DataRate",
                                 DataRateValue(DataRate((uint64_t)(cls.packetBytes * 8.0 * cls.ratePps))));
                src.SetAttribute("Tos", UintegerValue(MakeTos(cfg.dscp, cls.dscpDecimal)));
                src.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
                src.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
                apps.Add(src.Install(orchestrator.Get(0)));
            }
            else
            {
                PacketSinkHelper sink("ns3::UdpSocketFactory",
                                      InetSocketAddress(Ipv4Address::GetAny(), port));
                sinks.Add(sink.Install(orchestrator.Get(0)));

                OnOffHelper src("ns3::UdpSocketFactory",
                                InetSocketAddress(ifOrchA.GetAddress(0), port));
                src.SetAttribute("PacketSize", UintegerValue(cls.packetBytes));
                src.SetAttribute("DataRate",
                                 DataRateValue(DataRate((uint64_t)(cls.packetBytes * 8.0 * cls.ratePps))));
                src.SetAttribute("Tos", UintegerValue(MakeTos(cfg.dscp, cls.dscpDecimal)));
                src.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
                src.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
                apps.Add(src.Install(followers.Get(i)));
            }
        }
    }

    {
        // Forward background traffic to make sure the bottleneck is not just lightly loaded.
        PacketSinkHelper sink("ns3::UdpSocketFactory",
                              InetSocketAddress(Ipv4Address::GetAny(), bgPort));
        sinks.Add(sink.Install(bgDst.Get(0)));

        OnOffHelper bg("ns3::UdpSocketFactory",
                       InetSocketAddress(ifBgDstB.GetAddress(1), bgPort));
        bg.SetAttribute("PacketSize", UintegerValue(1400));
        bg.SetAttribute("DataRate", DataRateValue(DataRate((uint64_t)(cfg.bgRateMbps * 1000000.0))));
        bg.SetAttribute("Tos", UintegerValue(MakeTos(cfg.dscp, 0)));

        if (cfg.burstyBg)
        {
            bg.SetAttribute("OnTime", StringValue("ns3::ExponentialRandomVariable[Mean=0.15]"));
            bg.SetAttribute("OffTime", StringValue("ns3::ExponentialRandomVariable[Mean=0.05]"));
        }
        else
        {
            bg.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
            bg.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
        }

        apps.Add(bg.Install(bgSrc.Get(0)));
    }

    {
        PacketSinkHelper sink("ns3::UdpSocketFactory",
                              InetSocketAddress(Ipv4Address::GetAny(), bgPortRev));
        sinks.Add(sink.Install(bgDstRev.Get(0)));

        OnOffHelper bgRev("ns3::UdpSocketFactory",
                          InetSocketAddress(ifBgDstA.GetAddress(1), bgPortRev));
        bgRev.SetAttribute("PacketSize", UintegerValue(1400));
        bgRev.SetAttribute("DataRate", DataRateValue(DataRate((uint64_t)(cfg.bgRateMbps * 1000000.0))));
        bgRev.SetAttribute("Tos", UintegerValue(MakeTos(cfg.dscp, 0)));

        if (cfg.burstyBg)
        {
            bgRev.SetAttribute("OnTime", StringValue("ns3::ExponentialRandomVariable[Mean=0.15]"));
            bgRev.SetAttribute("OffTime", StringValue("ns3::ExponentialRandomVariable[Mean=0.05]"));
        }
        else
        {
            bgRev.SetAttribute("OnTime", StringValue("ns3::ConstantRandomVariable[Constant=1]"));
            bgRev.SetAttribute("OffTime", StringValue("ns3::ConstantRandomVariable[Constant=0]"));
        }

        apps.Add(bgRev.Install(bgSrcRev.Get(0)));
    }

    sinks.Start(Seconds(0.0));
    sinks.Stop(Seconds(cfg.simTime + 1.0));

    apps.Start(Seconds(1.0));
    apps.Stop(Seconds(cfg.simTime));

    FlowMonitorHelper flowHelper;
    Ptr<FlowMonitor> flowMon = flowHelper.InstallAll();

    Simulator::Stop(Seconds(cfg.simTime + 1.0));
    Simulator::Run();

    flowMon->CheckForLostPackets();
    Ptr<Ipv4FlowClassifier> classifier = DynamicCast<Ipv4FlowClassifier>(flowHelper.GetClassifier());
    auto stats = flowMon->GetFlowStats();

    bool writeHeader = false;
    {
        std::ifstream testRead(outFile);
        writeHeader = !testRead.good() || testRead.peek() == std::ifstream::traits_type::eof();
    }

    std::ofstream out(outFile, std::ios::app);
    if (!out.is_open())
    {
        std::cerr << "Failed to open CSV output: " << outFile << std::endl;
        Simulator::Destroy();
        return 1;
    }

    if (writeHeader)
    {
        out << "run_id,seed,scenario,scheduler_key,scheduler_label,dscp_mode,followers,bottleneck_mbps,queue_pkts,"
               "bg_rate_mbps,bursty_bg,flow_class,src,dst,src_port,dst_port,tx_packets,rx_packets,loss_pct,"
               "throughput_bps,delay_mean_ms,jitter_mean_ms\n";
    }

    // Apps start at 1 s, so this is the window I use for throughput math.
    const double activeDuration = cfg.simTime - 1.0;

    for (const auto& [flowId, st] : stats)
    {
        auto t = classifier->FindFlow(flowId);

        // Figure out which logical class this flow belongs to from its destination port.
        std::string flowClass = "other";

        for (const auto& cls : classes)
        {
            if (t.destinationPort >= cls.portBase && t.destinationPort < cls.portBase + cfg.followers)
            {
                flowClass = cls.name;
                break;
            }
        }

        if (t.destinationPort == bgPort || t.destinationPort == bgPortRev)
        {
            flowClass = "background";
        }

        if (flowClass == "other")
        {
            continue;
        }

        double lossPct = 0.0;
        if (st.txPackets > 0)
        {
            lossPct = 100.0 * (double)(st.txPackets - st.rxPackets) / (double)st.txPackets;
        }

        double throughputBps = 0.0;
        if (activeDuration > 0)
        {
            throughputBps = (st.rxBytes * 8.0) / activeDuration;
        }

        double delayMeanMs = 0.0;
        if (st.rxPackets > 0)
        {
            delayMeanMs = 1000.0 * st.delaySum.GetSeconds() / st.rxPackets;
        }

        double jitterMeanMs = 0.0;
        if (st.rxPackets > 1)
        {
            jitterMeanMs = 1000.0 * st.jitterSum.GetSeconds() / (st.rxPackets - 1);
        }

        out << cfg.runId << ","
            << RngSeedManager::GetRun() << ","
            << cfg.scenario << ","
            << cfg.scheduler << ","
            << "\"" << SchedulerLabel(cfg.scheduler) << "\"" << ","
            << (cfg.dscp ? "on" : "off") << ","
            << cfg.followers << ","
            << std::fixed << std::setprecision(3) << cfg.bottleneckMbps << ","
            << cfg.queuePkts << ","
            << cfg.bgRateMbps << ","
            << (cfg.burstyBg ? "yes" : "no") << ","
            << flowClass << ","
            << t.sourceAddress << ","
            << t.destinationAddress << ","
            << t.sourcePort << ","
            << t.destinationPort << ","
            << st.txPackets << ","
            << st.rxPackets << ","
            << std::fixed << std::setprecision(4) << lossPct << ","
            << throughputBps << ","
            << delayMeanMs << ","
            << jitterMeanMs << "\n";
    }

    out.close();
    Simulator::Destroy();
    return 0;
}
