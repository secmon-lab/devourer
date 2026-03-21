package logic

import (
	"context"
	"log/slog"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/secmon-lab/devourer/pkg/domain/interfaces"
	"github.com/secmon-lab/devourer/pkg/domain/model"
	"github.com/secmon-lab/devourer/pkg/utils"
)

type Engine struct {
	timeout    time.Duration
	flowMap    *FlowMap
	dnsTracker *DNSTracker
	repo       interfaces.Repository
}

func NewEngine(opts ...Option) *Engine {
	e := &Engine{
		timeout:    120 * time.Second,
		flowMap:    NewFlowMap(),
		dnsTracker: NewDNSTracker(),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

type Option func(*Engine)

func WithTimeout(d time.Duration) Option {
	return func(x *Engine) {
		x.timeout = d
	}
}

func WithRepository(repo interfaces.Repository) Option {
	return func(x *Engine) {
		x.repo = repo
	}
}

func (x *Engine) InputPacket(ctx context.Context, pkt gopacket.Packet) (*model.Record, error) {
	// Extract name resolution data from protocol-specific layers
	if x.repo != nil {
		ExtractNames(ctx, pkt, x.repo)
	}

	if pkt.NetworkLayer() == nil || pkt.TransportLayer() == nil {
		// not supported
		return nil, nil
	}

	netLayer := pkt.NetworkLayer().NetworkFlow()

	var proto string
	var sni string
	var srcPort, dstPort uint32
	switch pkt.TransportLayer().LayerType() {
	case layers.LayerTypeTCP:
		tcpLayer := pkt.TransportLayer().(*layers.TCP)
		srcPort = uint32(tcpLayer.SrcPort)
		dstPort = uint32(tcpLayer.DstPort)
		proto = "tcp"
		sni = extractTLSSNI(tcpLayer.Payload)
	case layers.LayerTypeUDP:
		udpLayer := pkt.TransportLayer().(*layers.UDP)
		srcPort = uint32(udpLayer.SrcPort)
		dstPort = uint32(udpLayer.DstPort)
		proto = "udp"
	case layers.LayerTypeICMPv4:
		proto = "icmp4"
	case layers.LayerTypeICMPv6:
		proto = "icmp6"
	default:
		// not supported
		return nil, nil
	}

	// Extract MAC addresses from Ethernet layer
	srcMAC, dstMAC := GetEthernetMACs(pkt)

	dstPeer := model.Peer{
		Addr:   netLayer.Dst().Raw(),
		Port:   dstPort,
		HWAddr: dstMAC,
	}
	if sni != "" {
		dstPeer.Names = []string{sni}
	}

	flow := model.NewFlow(
		model.Peer{
			Addr:   netLayer.Src().Raw(),
			Port:   srcPort,
			HWAddr: srcMAC,
		},
		dstPeer,
		proto,
		pkt.Metadata().Timestamp,
		model.PeerStat{
			Bytes:   uint64(pkt.Metadata().Length),
			Packets: 1,
		},
	)

	isNew := x.flowMap.Put(flow)

	// For existing flows, set SNI on the server peer if not already set
	if !isNew && sni != "" {
		serverIP := netLayer.Dst().Raw()
		x.flowMap.SetNames(flow.Key(), serverIP, []string{sni})
	}

	// Track DNS transactions
	dnsLogs := x.dnsTracker.Input(pkt, pkt.Metadata().Timestamp)

	return &model.Record{
		DNSLogs: dnsLogs,
	}, nil
}

func (x *Engine) Tick(ctx context.Context, now time.Time) (*model.Record, error) {
	flows := x.flowMap.Expire(now.Add(-x.timeout))
	x.enrichFlows(ctx, flows)
	dnsLogs := x.dnsTracker.Expire(now)
	return &model.Record{
		FlowLogs: flows,
		DNSLogs:  dnsLogs,
	}, nil
}

func (x *Engine) Flush(ctx context.Context) *model.Record {
	flows := x.flowMap.Flush()
	x.enrichFlows(ctx, flows)
	dnsLogs := x.dnsTracker.Flush()
	return &model.Record{
		FlowLogs: flows,
		DNSLogs:  dnsLogs,
	}
}

func (x *Engine) enrichFlows(ctx context.Context, flows []*model.Flow) {
	if x.repo == nil {
		return
	}

	for _, flow := range flows {
		x.enrichPeer(ctx, &flow.Src)
		x.enrichPeer(ctx, &flow.Dst)
	}
}

func (x *Engine) enrichPeer(ctx context.Context, peer *model.Peer) {
	// Skip repository lookup if names are already set (e.g., from TLS SNI)
	if len(peer.Names) > 0 {
		return
	}

	nameSet := make(map[string]struct{})

	// Try IP-based lookup first (DNS)
	names, err := x.repo.LookupByAddr(ctx, peer.Addr)
	if err != nil {
		utils.Logger().Warn("failed to lookup names by addr",
			slog.String("addr", peer.Addr.String()),
			slog.Any("error", err),
		)
	}
	for _, name := range names {
		nameSet[name] = struct{}{}
	}

	// Fallback to MAC-based lookup (mDNS/LLMNR/NBNS/DHCP)
	if peer.HWAddr != nil {
		hwNames, err := x.repo.LookupByHWAddr(ctx, peer.HWAddr)
		if err != nil {
			utils.Logger().Warn("failed to lookup names by hw addr",
				slog.String("hw_addr", peer.HWAddr.String()),
				slog.Any("error", err),
			)
		}
		for _, name := range hwNames {
			nameSet[name] = struct{}{}
		}
	}

	if len(nameSet) == 0 {
		return
	}

	uniqueNames := make([]string, 0, len(nameSet))
	for name := range nameSet {
		uniqueNames = append(uniqueNames, name)
	}
	peer.Names = uniqueNames
}

func (x *Engine) FlowCount() int {
	return x.flowMap.Len()
}
