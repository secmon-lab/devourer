package logic_test

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/m-mizutani/gt"
	"github.com/secmon-lab/devourer/pkg/domain/logic"
)

// buildTLSClientHello constructs a minimal TLS ClientHello message with the given SNI hostname.
func buildTLSClientHello(hostname string) []byte {
	// SNI extension data
	hostBytes := []byte(hostname)
	// ServerName entry: NameType(1) + NameLength(2) + Name
	serverName := []byte{0x00} // host_name type
	serverName = append(serverName, byte(len(hostBytes)>>8), byte(len(hostBytes)))
	serverName = append(serverName, hostBytes...)
	// ServerNameList: ListLength(2) + entries
	sniData := make([]byte, 2)
	binary.BigEndian.PutUint16(sniData, uint16(len(serverName)))
	sniData = append(sniData, serverName...)
	// Extension: Type(2) + Length(2) + Data
	sniExt := []byte{0x00, 0x00} // server_name extension type
	sniExt = append(sniExt, byte(len(sniData)>>8), byte(len(sniData)))
	sniExt = append(sniExt, sniData...)

	// Extensions block: Length(2) + extensions
	extensions := make([]byte, 2)
	binary.BigEndian.PutUint16(extensions, uint16(len(sniExt)))
	extensions = append(extensions, sniExt...)

	// ClientHello body:
	// Version(2) + Random(32) + SessionIDLen(1) + CipherSuitesLen(2) + CipherSuite(2) + CompMethodsLen(1) + CompMethod(1) + Extensions
	clientHello := []byte{0x03, 0x03} // TLS 1.2
	clientHello = append(clientHello, make([]byte, 32)...)   // Random
	clientHello = append(clientHello, 0x00)                  // SessionID length = 0
	clientHello = append(clientHello, 0x00, 0x02, 0x00, 0x2f) // CipherSuites: length=2, TLS_RSA_WITH_AES_128_CBC_SHA
	clientHello = append(clientHello, 0x01, 0x00)            // CompressionMethods: length=1, null
	clientHello = append(clientHello, extensions...)

	// Handshake header: Type(1) + Length(3)
	handshake := []byte{0x01} // ClientHello
	handshakeLen := len(clientHello)
	handshake = append(handshake, byte(handshakeLen>>16), byte(handshakeLen>>8), byte(handshakeLen))
	handshake = append(handshake, clientHello...)

	// TLS Record header: ContentType(1) + Version(2) + Length(2)
	record := []byte{0x16, 0x03, 0x01} // Handshake, TLS 1.0 record version
	recordLen := len(handshake)
	record = append(record, byte(recordLen>>8), byte(recordLen))
	record = append(record, handshake...)

	return record
}

func buildTCPPacket(t *testing.T, srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) gopacket.Packet {
	t.Helper()

	eth := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		DstMAC:       net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		SrcIP:    srcIP,
		DstIP:    dstIP,
		Protocol: layers.IPProtocolTCP,
		TTL:      64,
	}
	tcp := &layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		SYN:     false,
		ACK:     true,
	}
	gt.NoError(t, tcp.SetNetworkLayerForChecksum(ip))

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	err := gopacket.SerializeLayers(buf, opts, eth, ip, tcp, gopacket.Payload(payload))
	gt.NoError(t, err)

	return gopacket.NewPacket(buf.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
}

func TestTLSSNIExtraction(t *testing.T) {
	ctx := context.Background()
	engine := logic.NewEngine()

	clientHello := buildTLSClientHello("api.example.com")
	pkt := buildTCPPacket(t,
		net.IPv4(192, 168, 1, 100), // client
		net.IPv4(93, 184, 216, 34), // server
		54321, 443,
		clientHello,
	)
	pkt.Metadata().Timestamp = time.Now()
	pkt.Metadata().Length = len(pkt.Data())

	_, err := engine.InputPacket(ctx, pkt)
	gt.NoError(t, err)

	record := engine.Flush(ctx)
	gt.A(t, record.FlowLogs).Length(1)

	flow := record.FlowLogs[0]

	// Find the server peer (93.184.216.34:443) and verify SNI
	var serverNames []string
	if flow.Dst.Addr.Equal(net.IPv4(93, 184, 216, 34)) {
		serverNames = flow.Dst.Names
	} else {
		serverNames = flow.Src.Names
	}

	gt.A(t, serverNames).Length(1).Has("api.example.com")
}

func TestTLSSNIExtractionOnExistingFlow(t *testing.T) {
	ctx := context.Background()
	engine := logic.NewEngine()

	now := time.Now()
	clientIP := net.IPv4(192, 168, 1, 100)
	serverIP := net.IPv4(93, 184, 216, 34)

	// First packet: SYN (no payload, creates the flow)
	synPkt := buildTCPPacket(t, clientIP, serverIP, 54321, 443, nil)
	synPkt.Metadata().Timestamp = now
	synPkt.Metadata().Length = 66

	_, err := engine.InputPacket(ctx, synPkt)
	gt.NoError(t, err)

	// Second packet: ClientHello (SNI should be set on existing flow)
	clientHello := buildTLSClientHello("api.example.com")
	tlsPkt := buildTCPPacket(t, clientIP, serverIP, 54321, 443, clientHello)
	tlsPkt.Metadata().Timestamp = now.Add(time.Millisecond)
	tlsPkt.Metadata().Length = len(tlsPkt.Data())

	_, err = engine.InputPacket(ctx, tlsPkt)
	gt.NoError(t, err)

	record := engine.Flush(ctx)
	gt.A(t, record.FlowLogs).Length(1)

	flow := record.FlowLogs[0]

	var serverNames []string
	if flow.Dst.Addr.Equal(serverIP) {
		serverNames = flow.Dst.Names
	} else {
		serverNames = flow.Src.Names
	}

	gt.A(t, serverNames).Length(1).Has("api.example.com")
}
