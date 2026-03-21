package logic_test

import (
	"context"
	"net"
	"testing"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/m-mizutani/gt"
	"github.com/secmon-lab/devourer/pkg/domain/logic"
	"github.com/secmon-lab/devourer/pkg/infra/repo"
)

func buildPacket(t *testing.T, ethLayer *layers.Ethernet, ipLayer *layers.IPv4, udpLayer *layers.UDP, payloadLayers ...gopacket.SerializableLayer) gopacket.Packet {
	t.Helper()
	udpLayer.SetNetworkLayerForChecksum(ipLayer)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	allLayers := []gopacket.SerializableLayer{ethLayer, ipLayer, udpLayer}
	allLayers = append(allLayers, payloadLayers...)

	err := gopacket.SerializeLayers(buf, opts, allLayers...)
	gt.NoError(t, err)

	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func TestExtractDNS(t *testing.T) {
	ctx := context.Background()
	memRepo := repo.NewMemory()

	dns := &layers.DNS{
		QR:     true, // response
		QDCount: 1,
		ANCount: 1,
		Questions: []layers.DNSQuestion{
			{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
		},
		Answers: []layers.DNSResourceRecord{
			{
				Name:  []byte("example.com"),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				IP:    net.IPv4(93, 184, 216, 34),
			},
		},
	}

	pkt := buildPacket(t,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			DstMAC:       net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			SrcIP:    net.IPv4(8, 8, 8, 8),
			DstIP:    net.IPv4(192, 168, 1, 100),
			Protocol: layers.IPProtocolUDP,
		},
		&layers.UDP{
			SrcPort: 53,
			DstPort: 12345,
		},
		dns,
	)

	logic.ExtractNames(ctx, pkt, memRepo)

	names, err := memRepo.LookupByAddr(ctx, net.IPv4(93, 184, 216, 34))
	gt.NoError(t, err)
	gt.A(t, names).Length(1).Has("example.com")
}

func TestExtractDNSQuery(t *testing.T) {
	ctx := context.Background()
	memRepo := repo.NewMemory()

	dns := &layers.DNS{
		QR:      false, // query, not response
		QDCount: 1,
		Questions: []layers.DNSQuestion{
			{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
		},
	}

	pkt := buildPacket(t,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			DstMAC:       net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			SrcIP:    net.IPv4(192, 168, 1, 100),
			DstIP:    net.IPv4(8, 8, 8, 8),
			Protocol: layers.IPProtocolUDP,
		},
		&layers.UDP{
			SrcPort: 12345,
			DstPort: 53,
		},
		dns,
	)

	logic.ExtractNames(ctx, pkt, memRepo)

	// Query should not save anything
	names, err := memRepo.LookupByAddr(ctx, net.IPv4(93, 184, 216, 34))
	gt.NoError(t, err)
	gt.A(t, names).Length(0)
}

func TestExtractMDNS(t *testing.T) {
	ctx := context.Background()
	memRepo := repo.NewMemory()

	srcMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	dns := &layers.DNS{
		QR:      true,
		ANCount: 1,
		Answers: []layers.DNSResourceRecord{
			{
				Name:  []byte("my-laptop.local"),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				IP:    net.IPv4(192, 168, 1, 50),
			},
		},
	}

	pkt := buildPacket(t,
		&layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			SrcIP:    net.IPv4(192, 168, 1, 50),
			DstIP:    net.IPv4(224, 0, 0, 251),
			Protocol: layers.IPProtocolUDP,
		},
		&layers.UDP{
			SrcPort: 5353,
			DstPort: 5353,
		},
		dns,
	)

	logic.ExtractNames(ctx, pkt, memRepo)

	// mDNS should save MAC→name, not IP→name
	names, err := memRepo.LookupByHWAddr(ctx, srcMAC)
	gt.NoError(t, err)
	gt.A(t, names).Length(1).Has("my-laptop.local")

	// IP should NOT have name (mDNS saves to MAC)
	ipNames, err := memRepo.LookupByAddr(ctx, net.IPv4(192, 168, 1, 50))
	gt.NoError(t, err)
	gt.A(t, ipNames).Length(0)
}

func TestExtractLLMNR(t *testing.T) {
	ctx := context.Background()
	memRepo := repo.NewMemory()

	srcMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	dns := &layers.DNS{
		QR:      true,
		ANCount: 1,
		Answers: []layers.DNSResourceRecord{
			{
				Name:  []byte("workstation"),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				IP:    net.IPv4(192, 168, 1, 30),
			},
		},
	}

	pkt := buildPacket(t,
		&layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0xfc},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			SrcIP:    net.IPv4(192, 168, 1, 30),
			DstIP:    net.IPv4(224, 0, 0, 252),
			Protocol: layers.IPProtocolUDP,
		},
		&layers.UDP{
			SrcPort: 5355,
			DstPort: 5355,
		},
		dns,
	)

	logic.ExtractNames(ctx, pkt, memRepo)

	names, err := memRepo.LookupByHWAddr(ctx, srcMAC)
	gt.NoError(t, err)
	gt.A(t, names).Length(1).Has("workstation")
}

func TestExtractDHCP(t *testing.T) {
	ctx := context.Background()
	memRepo := repo.NewMemory()

	clientMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}

	dhcp := &layers.DHCPv4{
		Operation:    layers.DHCPOpRequest,
		HardwareType: layers.LinkTypeEthernet,
		HardwareLen:  6,
		ClientHWAddr: clientMAC,
		Options: layers.DHCPOptions{
			{
				Type:   layers.DHCPOptHostname,
				Data:   []byte("office-pc"),
				Length: 9,
			},
			{
				Type:   layers.DHCPOptMessageType,
				Data:   []byte{byte(layers.DHCPMsgTypeDiscover)},
				Length: 1,
			},
		},
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}

	ethLayer := &layers.Ethernet{
		SrcMAC:       clientMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ipLayer := &layers.IPv4{
		Version:  4,
		SrcIP:    net.IPv4(0, 0, 0, 0),
		DstIP:    net.IPv4(255, 255, 255, 255),
		Protocol: layers.IPProtocolUDP,
	}
	udpLayer := &layers.UDP{
		SrcPort: 68,
		DstPort: 67,
	}
	udpLayer.SetNetworkLayerForChecksum(ipLayer)

	err := gopacket.SerializeLayers(buf, opts, ethLayer, ipLayer, udpLayer, dhcp)
	gt.NoError(t, err)

	pkt := gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	logic.ExtractNames(ctx, pkt, memRepo)

	names, err := memRepo.LookupByHWAddr(ctx, clientMAC)
	gt.NoError(t, err)
	gt.A(t, names).Length(1).Has("office-pc")
}

func TestGetEthernetMACs(t *testing.T) {
	srcMAC := net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	dstMAC := net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66}

	pkt := buildPacket(t,
		&layers.Ethernet{
			SrcMAC:       srcMAC,
			DstMAC:       dstMAC,
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			SrcIP:    net.IPv4(192, 168, 1, 1),
			DstIP:    net.IPv4(192, 168, 1, 2),
			Protocol: layers.IPProtocolUDP,
		},
		&layers.UDP{
			SrcPort: 12345,
			DstPort: 80,
		},
		gopacket.Payload([]byte("test")),
	)

	gotSrcMAC, gotDstMAC := logic.GetEthernetMACs(pkt)
	gt.V(t, gotSrcMAC.String()).Equal(srcMAC.String())
	gt.V(t, gotDstMAC.String()).Equal(dstMAC.String())
}

