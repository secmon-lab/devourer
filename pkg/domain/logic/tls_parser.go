package logic

import "encoding/binary"

// extractTLSSNI extracts the Server Name Indication (SNI) hostname from a TLS ClientHello message.
// Returns empty string if the payload is not a valid TLS ClientHello or does not contain SNI.
func extractTLSSNI(payload []byte) string {
	// TLS Record Header: ContentType(1) + Version(2) + Length(2) = 5 bytes minimum
	if len(payload) < 5 {
		return ""
	}

	// ContentType must be Handshake (0x16)
	if payload[0] != 0x16 {
		return ""
	}

	recordLen := int(binary.BigEndian.Uint16(payload[3:5]))
	payload = payload[5:]
	if len(payload) < recordLen {
		return ""
	}
	payload = payload[:recordLen]

	// Handshake Header: HandshakeType(1) + Length(3) = 4 bytes
	if len(payload) < 4 {
		return ""
	}

	// HandshakeType must be ClientHello (0x01)
	if payload[0] != 0x01 {
		return ""
	}

	payload = payload[4:]

	// ClientHello body:
	// Version(2) + Random(32) = 34 bytes minimum
	if len(payload) < 34 {
		return ""
	}
	payload = payload[34:]

	// SessionID: Length(1) + variable
	if len(payload) < 1 {
		return ""
	}
	sessionIDLen := int(payload[0])
	payload = payload[1:]
	if len(payload) < sessionIDLen {
		return ""
	}
	payload = payload[sessionIDLen:]

	// CipherSuites: Length(2) + variable
	if len(payload) < 2 {
		return ""
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(payload[0:2]))
	payload = payload[2:]
	if len(payload) < cipherSuitesLen {
		return ""
	}
	payload = payload[cipherSuitesLen:]

	// CompressionMethods: Length(1) + variable
	if len(payload) < 1 {
		return ""
	}
	compMethodsLen := int(payload[0])
	payload = payload[1:]
	if len(payload) < compMethodsLen {
		return ""
	}
	payload = payload[compMethodsLen:]

	// Extensions: Length(2) + variable
	if len(payload) < 2 {
		return ""
	}
	extensionsLen := int(binary.BigEndian.Uint16(payload[0:2]))
	payload = payload[2:]
	if len(payload) < extensionsLen {
		return ""
	}
	payload = payload[:extensionsLen]

	// Iterate extensions looking for server_name (0x0000)
	for len(payload) >= 4 {
		extType := binary.BigEndian.Uint16(payload[0:2])
		extLen := int(binary.BigEndian.Uint16(payload[2:4]))
		payload = payload[4:]
		if len(payload) < extLen {
			return ""
		}

		if extType == 0x0000 {
			return parseSNIExtension(payload[:extLen])
		}

		payload = payload[extLen:]
	}

	return ""
}

// parseSNIExtension parses the SNI extension data to extract the host_name.
// Format: ServerNameListLength(2) + [NameType(1) + NameLength(2) + Name(variable)]*
func parseSNIExtension(data []byte) string {
	if len(data) < 2 {
		return ""
	}

	listLen := int(binary.BigEndian.Uint16(data[0:2]))
	data = data[2:]
	if len(data) < listLen {
		return ""
	}
	data = data[:listLen]

	for len(data) >= 3 {
		nameType := data[0]
		nameLen := int(binary.BigEndian.Uint16(data[1:3]))
		data = data[3:]
		if len(data) < nameLen {
			return ""
		}

		// NameType 0x00 = host_name
		if nameType == 0x00 && nameLen > 0 {
			return string(data[:nameLen])
		}

		data = data[nameLen:]
	}

	return ""
}
