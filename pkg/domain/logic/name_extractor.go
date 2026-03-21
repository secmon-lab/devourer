package logic

import (
	"context"
	"encoding/binary"
	"log/slog"
	"net"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/secmon-lab/devourer/pkg/domain/interfaces"
	"github.com/secmon-lab/devourer/pkg/utils"
)

// ExtractNames parses protocol-specific information from a packet
// and saves name resolution data (IP→name, MAC→name) to the repository.
func ExtractNames(ctx context.Context, pkt gopacket.Packet, repo interfaces.Repository) {
	udpLayer, isUDP := getUDPLayer(pkt)

	if isUDP {
		srcPort := uint16(udpLayer.SrcPort)
		dstPort := uint16(udpLayer.DstPort)

		switch {
		case srcPort == 53 || dstPort == 53:
			extractDNS(ctx, pkt, repo)
		case srcPort == 5353 || dstPort == 5353:
			extractMDNS(ctx, pkt, repo)
		case srcPort == 5355 || dstPort == 5355:
			extractLLMNR(ctx, pkt, repo)
		case srcPort == 137 || dstPort == 137:
			extractNBNS(ctx, pkt, repo)
		case srcPort == 67 || srcPort == 68 || dstPort == 67 || dstPort == 68:
			extractDHCP(ctx, pkt, repo)
		}
	}
}

// GetEthernetMACs extracts source and destination MAC addresses from the Ethernet layer.
func GetEthernetMACs(pkt gopacket.Packet) (srcMAC, dstMAC net.HardwareAddr) {
	ethLayer := pkt.Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return nil, nil
	}
	eth := ethLayer.(*layers.Ethernet)
	return eth.SrcMAC, eth.DstMAC
}

func getUDPLayer(pkt gopacket.Packet) (*layers.UDP, bool) {
	l := pkt.Layer(layers.LayerTypeUDP)
	if l == nil {
		return nil, false
	}
	return l.(*layers.UDP), true
}

func getDNSLayer(pkt gopacket.Packet) (*layers.DNS, bool) {
	l := pkt.Layer(layers.LayerTypeDNS)
	if l == nil {
		return nil, false
	}
	return l.(*layers.DNS), true
}

// parseDNSFromUDP decodes DNS from UDP payload manually,
// for protocols that use DNS format but on non-standard ports (mDNS, LLMNR, NBNS).
func parseDNSFromUDP(pkt gopacket.Packet) (*layers.DNS, bool) {
	// First try the standard DNS layer
	if dns, ok := getDNSLayer(pkt); ok {
		return dns, true
	}

	// Manually decode from UDP payload
	udpLayer, ok := getUDPLayer(pkt)
	if !ok {
		return nil, false
	}

	dns := &layers.DNS{}
	if err := dns.DecodeFromBytes(udpLayer.Payload, gopacket.NilDecodeFeedback); err != nil {
		return nil, false
	}
	return dns, true
}

// extractDNS extracts A/AAAA records from DNS responses and saves IP→name mappings.
func extractDNS(ctx context.Context, pkt gopacket.Packet, repo interfaces.Repository) {
	dns, ok := getDNSLayer(pkt)
	if !ok {
		return
	}

	// Only process responses
	if !dns.QR {
		return
	}

	for _, answer := range dns.Answers {
		if answer.Type != layers.DNSTypeA && answer.Type != layers.DNSTypeAAAA {
			continue
		}
		if answer.IP == nil {
			continue
		}

		name := normalizeDNSName(string(answer.Name))
		if name == "" {
			continue
		}

		if err := repo.SaveAddrName(ctx, answer.IP, name); err != nil {
			utils.Logger().Debug("failed to save DNS name",
				slog.String("name", name),
				slog.String("addr", answer.IP.String()),
				slog.Any("error", err),
			)
		}
	}
}

// extractMDNS extracts A/AAAA records from mDNS responses and saves MAC→name mappings.
func extractMDNS(ctx context.Context, pkt gopacket.Packet, repo interfaces.Repository) {
	dns, ok := parseDNSFromUDP(pkt)
	if !ok {
		return
	}

	if !dns.QR {
		return
	}

	srcMAC, _ := GetEthernetMACs(pkt)
	if srcMAC == nil {
		return
	}

	for _, answer := range dns.Answers {
		if answer.Type != layers.DNSTypeA && answer.Type != layers.DNSTypeAAAA {
			continue
		}

		name := normalizeDNSName(string(answer.Name))
		if name == "" {
			continue
		}

		if err := repo.SaveHWAddrName(ctx, srcMAC, name); err != nil {
			utils.Logger().Debug("failed to save mDNS name",
				slog.String("name", name),
				slog.String("hw_addr", srcMAC.String()),
				slog.Any("error", err),
			)
		}
	}
}

// extractLLMNR extracts A/AAAA records from LLMNR responses and saves MAC→name mappings.
func extractLLMNR(ctx context.Context, pkt gopacket.Packet, repo interfaces.Repository) {
	// LLMNR uses DNS packet format
	dns, ok := parseDNSFromUDP(pkt)
	if !ok {
		return
	}

	if !dns.QR {
		return
	}

	srcMAC, _ := GetEthernetMACs(pkt)
	if srcMAC == nil {
		return
	}

	for _, answer := range dns.Answers {
		if answer.Type != layers.DNSTypeA && answer.Type != layers.DNSTypeAAAA {
			continue
		}

		name := normalizeDNSName(string(answer.Name))
		if name == "" {
			continue
		}

		if err := repo.SaveHWAddrName(ctx, srcMAC, name); err != nil {
			utils.Logger().Debug("failed to save LLMNR name",
				slog.String("name", name),
				slog.String("hw_addr", srcMAC.String()),
				slog.Any("error", err),
			)
		}
	}
}

// extractNBNS extracts name registrations/responses from NetBIOS Name Service packets.
// NBNS uses a DNS-like format but gopacket doesn't have a dedicated layer,
// so we parse the DNS layer which covers the basic structure.
func extractNBNS(ctx context.Context, pkt gopacket.Packet, repo interfaces.Repository) {
	// NBNS uses DNS-like format; try parsing as DNS first
	dns, ok := parseDNSFromUDP(pkt)
	if ok && dns.QR {
		srcMAC, _ := GetEthernetMACs(pkt)
		if srcMAC == nil {
			return
		}

		for _, answer := range dns.Answers {
			name := decodeNetBIOSName(string(answer.Name))
			if name == "" {
				continue
			}

			if err := repo.SaveHWAddrName(ctx, srcMAC, name); err != nil {
				utils.Logger().Debug("failed to save NBNS name",
					slog.String("name", name),
					slog.String("hw_addr", srcMAC.String()),
					slog.Any("error", err),
				)
			}
		}
		return
	}

	// Fallback: manually parse NBNS from UDP payload for registration packets
	udpLayer, isUDP := getUDPLayer(pkt)
	if !isUDP {
		return
	}

	srcMAC, _ := GetEthernetMACs(pkt)
	if srcMAC == nil {
		return
	}

	payload := udpLayer.Payload
	if len(payload) < 12 {
		return
	}

	// NBNS header: 2 bytes ID, 2 bytes flags, 2 bytes QDCOUNT, etc.
	flags := binary.BigEndian.Uint16(payload[2:4])
	opcode := (flags >> 11) & 0xF

	// opcode 5 = Registration, opcode 0 with response = Name Query Response
	isResponse := (flags & 0x8000) != 0
	if !isResponse && opcode != 5 {
		return
	}

	// Try to extract the name from the question/additional section
	name := parseNBNSNameFromPayload(payload[12:])
	if name == "" {
		return
	}

	if err := repo.SaveHWAddrName(ctx, srcMAC, name); err != nil {
		utils.Logger().Debug("failed to save NBNS name from payload",
			slog.String("name", name),
			slog.String("hw_addr", srcMAC.String()),
			slog.Any("error", err),
		)
	}
}

// extractDHCP extracts hostname from DHCP Option 12 and saves MAC→name mapping.
func extractDHCP(ctx context.Context, pkt gopacket.Packet, repo interfaces.Repository) {
	dhcpLayer := pkt.Layer(layers.LayerTypeDHCPv4)
	if dhcpLayer == nil {
		return
	}
	dhcp := dhcpLayer.(*layers.DHCPv4)

	var hostname string
	for _, opt := range dhcp.Options {
		if opt.Type == layers.DHCPOptHostname {
			hostname = string(opt.Data)
			break
		}
	}

	if hostname == "" {
		return
	}

	clientMAC := dhcp.ClientHWAddr
	if clientMAC == nil {
		return
	}

	if err := repo.SaveHWAddrName(ctx, clientMAC, hostname); err != nil {
		utils.Logger().Debug("failed to save DHCP hostname",
			slog.String("name", hostname),
			slog.String("hw_addr", clientMAC.String()),
			slog.Any("error", err),
		)
	}
}

// normalizeDNSName removes trailing dot from DNS names.
func normalizeDNSName(name string) string {
	return strings.TrimSuffix(name, ".")
}

// decodeNetBIOSName decodes a NetBIOS encoded name.
// NetBIOS names are encoded as pairs of characters where each pair represents
// a single character: first_char = ((byte1 - 'A') << 4) | (byte2 - 'A')
func decodeNetBIOSName(encoded string) string {
	if len(encoded) < 32 {
		return ""
	}

	var decoded []byte
	for i := 0; i < 32; i += 2 {
		b1 := encoded[i]
		b2 := encoded[i+1]
		if b1 < 'A' || b1 > 'P' || b2 < 'A' || b2 > 'P' {
			return ""
		}
		ch := ((b1 - 'A') << 4) | (b2 - 'A')
		decoded = append(decoded, ch)
	}

	// NetBIOS names are padded with spaces, trim them
	// Last byte is the name type suffix, strip it
	name := strings.TrimRight(string(decoded[:15]), " ")
	return name
}

// parseNBNSNameFromPayload attempts to parse a NetBIOS name from raw NBNS payload
// starting after the 12-byte header.
func parseNBNSNameFromPayload(data []byte) string {
	if len(data) < 1 {
		return ""
	}

	// First byte is the length of the name field
	nameLen := int(data[0])
	if nameLen == 0 || len(data) < 1+nameLen {
		return ""
	}

	return decodeNetBIOSName(string(data[1 : 1+nameLen]))
}
