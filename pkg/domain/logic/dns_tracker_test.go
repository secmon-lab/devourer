package logic_test

import (
	"net"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/m-mizutani/gt"
	"github.com/secmon-lab/devourer/pkg/domain/logic"
	"github.com/secmon-lab/devourer/pkg/domain/model"
)

func buildDNSQueryPacket(t *testing.T, txID uint16, clientIP, serverIP net.IP, clientPort uint16, questions []layers.DNSQuestion) gopacket.Packet {
	t.Helper()
	dns := &layers.DNS{
		ID:      txID,
		QR:      false,
		QDCount: uint16(len(questions)),
		Questions: questions,
	}
	return buildPacket(t,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			DstMAC:       net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			SrcIP:    clientIP,
			DstIP:    serverIP,
			Protocol: layers.IPProtocolUDP,
		},
		&layers.UDP{
			SrcPort: layers.UDPPort(clientPort),
			DstPort: 53,
		},
		dns,
	)
}

func buildDNSResponsePacket(t *testing.T, txID uint16, serverIP, clientIP net.IP, clientPort uint16, questions []layers.DNSQuestion, answers []layers.DNSResourceRecord, rcode layers.DNSResponseCode) gopacket.Packet {
	t.Helper()
	dns := &layers.DNS{
		ID:           txID,
		QR:           true,
		QDCount:      uint16(len(questions)),
		ANCount:      uint16(len(answers)),
		Questions:    questions,
		Answers:      answers,
		ResponseCode: rcode,
	}
	return buildPacket(t,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
			DstMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			SrcIP:    serverIP,
			DstIP:    clientIP,
			Protocol: layers.IPProtocolUDP,
		},
		&layers.UDP{
			SrcPort: 53,
			DstPort: layers.UDPPort(clientPort),
		},
		dns,
	)
}

var (
	testClientIP = net.IPv4(192, 168, 1, 100)
	testServerIP = net.IPv4(8, 8, 8, 8)
	testQuestions = []layers.DNSQuestion{
		{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
	}
	testAnswers = []layers.DNSResourceRecord{
		{
			Name:  []byte("example.com"),
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
			IP:    net.IPv4(93, 184, 216, 34),
			TTL:   300,
		},
	}
)

func TestDNSTracker_Resolved(t *testing.T) {
	tracker := logic.NewDNSTracker()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Send query
	queryPkt := buildDNSQueryPacket(t, 0x1234, testClientIP, testServerIP, 12345, testQuestions)
	logs := tracker.Input(queryPkt, now)
	gt.A(t, logs).Length(0) // Query returns no logs

	gt.V(t, tracker.PendingCount()).Equal(1)

	// Send matching response
	respTime := now.Add(50 * time.Millisecond)
	respPkt := buildDNSResponsePacket(t, 0x1234, testServerIP, testClientIP, 12345, testQuestions, testAnswers, layers.DNSResponseCodeNoErr)
	logs = tracker.Input(respPkt, respTime)
	gt.A(t, logs).Length(1)

	log := logs[0]
	gt.V(t, log.Status).Equal(model.DNSStatusResolved)
	gt.V(t, log.TransactionID).Equal(uint16(0x1234))
	gt.V(t, log.ClientAddr.String()).Equal(testClientIP.String())
	gt.V(t, log.ClientPort).Equal(uint32(12345))
	gt.V(t, log.ServerAddr.String()).Equal(testServerIP.String())
	gt.V(t, log.ServerPort).Equal(uint32(53))
	gt.V(t, log.ResponseCode).Equal("NOERROR")

	// QueryAt and ResponseAt should both be set
	gt.V(t, log.QueryAt).NotEqual((*time.Time)(nil))
	gt.V(t, log.ResponseAt).NotEqual((*time.Time)(nil))
	gt.V(t, *log.QueryAt).Equal(now)
	gt.V(t, *log.ResponseAt).Equal(respTime)

	// Questions should use the pending query's questions (from the original query)
	gt.A(t, log.Questions).Length(1)
	gt.V(t, log.Questions[0].Name).Equal("example.com")
	gt.V(t, log.Questions[0].Type).Equal("A")

	// Answers
	gt.A(t, log.Answers).Length(1)
	gt.V(t, log.Answers[0].Name).Equal("example.com")
	gt.V(t, log.Answers[0].Type).Equal("A")
	gt.V(t, log.Answers[0].Value).Equal("93.184.216.34")
	gt.V(t, log.Answers[0].TTL).Equal(int64(300))

	// Pending should be cleared
	gt.V(t, tracker.PendingCount()).Equal(0)
}

func TestDNSTracker_ResponseOnly(t *testing.T) {
	tracker := logic.NewDNSTracker()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Send response without prior query
	respPkt := buildDNSResponsePacket(t, 0x5678, testServerIP, testClientIP, 54321, testQuestions, testAnswers, layers.DNSResponseCodeNoErr)
	logs := tracker.Input(respPkt, now)
	gt.A(t, logs).Length(1)

	log := logs[0]
	gt.V(t, log.Status).Equal(model.DNSStatusResponseOnly)
	gt.V(t, log.TransactionID).Equal(uint16(0x5678))
	gt.V(t, log.ClientAddr.String()).Equal(testClientIP.String())
	gt.V(t, log.ClientPort).Equal(uint32(54321))
	gt.V(t, log.ServerAddr.String()).Equal(testServerIP.String())
	gt.V(t, log.ServerPort).Equal(uint32(53))

	// QueryAt should be nil, ResponseAt should be set
	gt.V(t, log.QueryAt).Equal((*time.Time)(nil))
	gt.V(t, log.ResponseAt).NotEqual((*time.Time)(nil))
	gt.V(t, *log.ResponseAt).Equal(now)

	// Questions from the response packet
	gt.A(t, log.Questions).Length(1)
	gt.V(t, log.Questions[0].Name).Equal("example.com")

	// Answers
	gt.A(t, log.Answers).Length(1)

	gt.V(t, tracker.PendingCount()).Equal(0)
}

func TestDNSTracker_Timeout(t *testing.T) {
	tracker := logic.NewDNSTracker()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Send query
	queryPkt := buildDNSQueryPacket(t, 0xABCD, testClientIP, testServerIP, 11111, testQuestions)
	logs := tracker.Input(queryPkt, now)
	gt.A(t, logs).Length(0)

	// Expire before timeout (119s) — should not expire
	logs = tracker.Expire(now.Add(119 * time.Second))
	gt.A(t, logs).Length(0)
	gt.V(t, tracker.PendingCount()).Equal(1)

	// Expire after timeout (121s) — should expire
	logs = tracker.Expire(now.Add(121 * time.Second))
	gt.A(t, logs).Length(1)

	log := logs[0]
	gt.V(t, log.Status).Equal(model.DNSStatusTimeout)
	gt.V(t, log.TransactionID).Equal(uint16(0xABCD))
	gt.V(t, log.ClientAddr.String()).Equal(testClientIP.String())
	gt.V(t, log.ClientPort).Equal(uint32(11111))

	// QueryAt should be set, ResponseAt should be nil
	gt.V(t, log.QueryAt).NotEqual((*time.Time)(nil))
	gt.V(t, *log.QueryAt).Equal(now)
	gt.V(t, log.ResponseAt).Equal((*time.Time)(nil))

	// No answers, empty response code
	gt.V(t, log.ResponseCode).Equal("")
	gt.A(t, log.Answers).Length(0)

	// Questions should be preserved
	gt.A(t, log.Questions).Length(1)
	gt.V(t, log.Questions[0].Name).Equal("example.com")

	gt.V(t, tracker.PendingCount()).Equal(0)
}

func TestDNSTracker_MultipleQuestions(t *testing.T) {
	tracker := logic.NewDNSTracker()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	multiQuestions := []layers.DNSQuestion{
		{Name: []byte("example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
		{Name: []byte("example.com"), Type: layers.DNSTypeAAAA, Class: layers.DNSClassIN},
	}

	multiAnswers := []layers.DNSResourceRecord{
		{
			Name:  []byte("example.com"),
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
			IP:    net.IPv4(93, 184, 216, 34),
			TTL:   300,
		},
		{
			Name:  []byte("example.com"),
			Type:  layers.DNSTypeAAAA,
			Class: layers.DNSClassIN,
			IP:    net.ParseIP("2606:2800:220:1:248:1893:25c8:1946"),
			TTL:   300,
		},
	}

	queryPkt := buildDNSQueryPacket(t, 0x1111, testClientIP, testServerIP, 22222, multiQuestions)
	tracker.Input(queryPkt, now)

	respPkt := buildDNSResponsePacket(t, 0x1111, testServerIP, testClientIP, 22222, multiQuestions, multiAnswers, layers.DNSResponseCodeNoErr)
	logs := tracker.Input(respPkt, now.Add(10*time.Millisecond))
	gt.A(t, logs).Length(1)

	log := logs[0]
	gt.V(t, log.Status).Equal(model.DNSStatusResolved)

	// Both questions should be captured
	gt.A(t, log.Questions).Length(2)
	gt.V(t, log.Questions[0].Type).Equal("A")
	gt.V(t, log.Questions[1].Type).Equal("AAAA")

	// Both answers should be captured
	gt.A(t, log.Answers).Length(2)
	gt.V(t, log.Answers[0].Type).Equal("A")
	gt.V(t, log.Answers[0].Value).Equal("93.184.216.34")
	gt.V(t, log.Answers[1].Type).Equal("AAAA")
	gt.V(t, log.Answers[1].Value).Equal("2606:2800:220:1:248:1893:25c8:1946")
}

func TestDNSTracker_AnswerTypes(t *testing.T) {
	tracker := logic.NewDNSTracker()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("CNAME answer", func(t *testing.T) {
		answers := []layers.DNSResourceRecord{
			{
				Name:  []byte("www.example.com"),
				Type:  layers.DNSTypeCNAME,
				Class: layers.DNSClassIN,
				CNAME: []byte("example.com."),
				TTL:   3600,
			},
			{
				Name:  []byte("example.com"),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				IP:    net.IPv4(93, 184, 216, 34),
				TTL:   300,
			},
		}
		questions := []layers.DNSQuestion{
			{Name: []byte("www.example.com"), Type: layers.DNSTypeA, Class: layers.DNSClassIN},
		}

		// Response only (no prior query) for simplicity
		respPkt := buildDNSResponsePacket(t, 0x2001, testServerIP, testClientIP, 33001, questions, answers, layers.DNSResponseCodeNoErr)
		logs := tracker.Input(respPkt, now)
		gt.A(t, logs).Length(1)
		gt.A(t, logs[0].Answers).Length(2)
		gt.V(t, logs[0].Answers[0].Type).Equal("CNAME")
		gt.V(t, logs[0].Answers[0].Value).Equal("example.com") // trailing dot normalized
		gt.V(t, logs[0].Answers[0].TTL).Equal(int64(3600))
		gt.V(t, logs[0].Answers[1].Type).Equal("A")
		gt.V(t, logs[0].Answers[1].Value).Equal("93.184.216.34")
	})

	t.Run("MX answer", func(t *testing.T) {
		answers := []layers.DNSResourceRecord{
			{
				Name:  []byte("example.com"),
				Type:  layers.DNSTypeMX,
				Class: layers.DNSClassIN,
				MX: layers.DNSMX{
					Preference: 10,
					Name:       []byte("mail.example.com."),
				},
				TTL: 3600,
			},
		}
		questions := []layers.DNSQuestion{
			{Name: []byte("example.com"), Type: layers.DNSTypeMX, Class: layers.DNSClassIN},
		}

		respPkt := buildDNSResponsePacket(t, 0x2002, testServerIP, testClientIP, 33002, questions, answers, layers.DNSResponseCodeNoErr)
		logs := tracker.Input(respPkt, now)
		gt.A(t, logs).Length(1)
		gt.A(t, logs[0].Answers).Length(1)
		gt.V(t, logs[0].Answers[0].Type).Equal("MX")
		gt.V(t, logs[0].Answers[0].Value).Equal("10 mail.example.com")
	})

	t.Run("AAAA answer", func(t *testing.T) {
		answers := []layers.DNSResourceRecord{
			{
				Name:  []byte("example.com"),
				Type:  layers.DNSTypeAAAA,
				Class: layers.DNSClassIN,
				IP:    net.ParseIP("2001:db8::1"),
				TTL:   600,
			},
		}
		questions := []layers.DNSQuestion{
			{Name: []byte("example.com"), Type: layers.DNSTypeAAAA, Class: layers.DNSClassIN},
		}

		respPkt := buildDNSResponsePacket(t, 0x2003, testServerIP, testClientIP, 33003, questions, answers, layers.DNSResponseCodeNoErr)
		logs := tracker.Input(respPkt, now)
		gt.A(t, logs).Length(1)
		gt.V(t, logs[0].Answers[0].Type).Equal("AAAA")
		gt.V(t, logs[0].Answers[0].Value).Equal("2001:db8::1")
		gt.V(t, logs[0].Answers[0].TTL).Equal(int64(600))
	})
}

func TestDNSTracker_DifferentClientsWithSameTxID(t *testing.T) {
	tracker := logic.NewDNSTracker()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	client1 := net.IPv4(192, 168, 1, 10)
	client2 := net.IPv4(192, 168, 1, 20)

	// Both clients send queries with same TX ID
	q1 := buildDNSQueryPacket(t, 0xAAAA, client1, testServerIP, 10001, testQuestions)
	q2 := buildDNSQueryPacket(t, 0xAAAA, client2, testServerIP, 10002, testQuestions)
	tracker.Input(q1, now)
	tracker.Input(q2, now)

	gt.V(t, tracker.PendingCount()).Equal(2)

	// Response to client1 only
	resp1 := buildDNSResponsePacket(t, 0xAAAA, testServerIP, client1, 10001, testQuestions, testAnswers, layers.DNSResponseCodeNoErr)
	logs := tracker.Input(resp1, now.Add(10*time.Millisecond))
	gt.A(t, logs).Length(1)
	gt.V(t, logs[0].ClientAddr.String()).Equal(client1.String())
	gt.V(t, logs[0].Status).Equal(model.DNSStatusResolved)

	// client2's query should still be pending
	gt.V(t, tracker.PendingCount()).Equal(1)
}

func TestDNSTracker_DuplicateQueryOverwrites(t *testing.T) {
	tracker := logic.NewDNSTracker()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// First query
	q1 := buildDNSQueryPacket(t, 0xBBBB, testClientIP, testServerIP, 12345, testQuestions)
	tracker.Input(q1, now)

	// Second query with same key (overwrites)
	later := now.Add(5 * time.Second)
	q2 := buildDNSQueryPacket(t, 0xBBBB, testClientIP, testServerIP, 12345, testQuestions)
	tracker.Input(q2, later)

	// Still only 1 pending
	gt.V(t, tracker.PendingCount()).Equal(1)

	// Response arrives — should use the latest query time
	resp := buildDNSResponsePacket(t, 0xBBBB, testServerIP, testClientIP, 12345, testQuestions, testAnswers, layers.DNSResponseCodeNoErr)
	logs := tracker.Input(resp, later.Add(10*time.Millisecond))
	gt.A(t, logs).Length(1)
	gt.V(t, *logs[0].QueryAt).Equal(later) // Should use the overwritten (later) query time
}

func TestDNSTracker_NXDomainResponse(t *testing.T) {
	tracker := logic.NewDNSTracker()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	queryPkt := buildDNSQueryPacket(t, 0xCCCC, testClientIP, testServerIP, 44444, testQuestions)
	tracker.Input(queryPkt, now)

	// Response with NXDomain, no answers
	respPkt := buildDNSResponsePacket(t, 0xCCCC, testServerIP, testClientIP, 44444, testQuestions, nil, layers.DNSResponseCodeNXDomain)
	logs := tracker.Input(respPkt, now.Add(20*time.Millisecond))
	gt.A(t, logs).Length(1)

	log := logs[0]
	gt.V(t, log.Status).Equal(model.DNSStatusResolved)
	gt.V(t, log.ResponseCode).Equal("NXDOMAIN")
	gt.A(t, log.Answers).Length(0)
}

func TestDNSTracker_PartialExpire(t *testing.T) {
	tracker := logic.NewDNSTracker()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Query 1 at t=0
	q1 := buildDNSQueryPacket(t, 0x0001, testClientIP, testServerIP, 10001, testQuestions)
	tracker.Input(q1, now)

	// Query 2 at t=60s
	q2 := buildDNSQueryPacket(t, 0x0002, testClientIP, testServerIP, 10002, testQuestions)
	tracker.Input(q2, now.Add(60*time.Second))

	gt.V(t, tracker.PendingCount()).Equal(2)

	// Expire at t=121s — only query 1 should expire (120s since t=0)
	logs := tracker.Expire(now.Add(121 * time.Second))
	gt.A(t, logs).Length(1)
	gt.V(t, logs[0].TransactionID).Equal(uint16(0x0001))
	gt.V(t, logs[0].Status).Equal(model.DNSStatusTimeout)

	// Query 2 still pending
	gt.V(t, tracker.PendingCount()).Equal(1)

	// Expire at t=181s — query 2 should expire (120s since t=60)
	logs = tracker.Expire(now.Add(181 * time.Second))
	gt.A(t, logs).Length(1)
	gt.V(t, logs[0].TransactionID).Equal(uint16(0x0002))

	gt.V(t, tracker.PendingCount()).Equal(0)
}

func TestDNSTracker_ResponseBeforeExpireNoDuplicate(t *testing.T) {
	tracker := logic.NewDNSTracker()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Send query
	queryPkt := buildDNSQueryPacket(t, 0xDDDD, testClientIP, testServerIP, 55555, testQuestions)
	tracker.Input(queryPkt, now)

	// Response arrives at t=30s (resolved)
	respPkt := buildDNSResponsePacket(t, 0xDDDD, testServerIP, testClientIP, 55555, testQuestions, testAnswers, layers.DNSResponseCodeNoErr)
	logs := tracker.Input(respPkt, now.Add(30*time.Second))
	gt.A(t, logs).Length(1)
	gt.V(t, logs[0].Status).Equal(model.DNSStatusResolved)

	// Expire at t=121s — should NOT produce duplicate log
	logs = tracker.Expire(now.Add(121 * time.Second))
	gt.A(t, logs).Length(0)
}

func TestDNSTracker_FlushWithPending(t *testing.T) {
	tracker := logic.NewDNSTracker()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Add 3 pending queries
	for i := uint16(1); i <= 3; i++ {
		q := buildDNSQueryPacket(t, i, testClientIP, testServerIP, 10000+i, testQuestions)
		tracker.Input(q, now)
	}
	gt.V(t, tracker.PendingCount()).Equal(3)

	// Flush should return all as timeout
	logs := tracker.Flush()
	gt.A(t, logs).Length(3)
	for _, log := range logs {
		gt.V(t, log.Status).Equal(model.DNSStatusTimeout)
		gt.V(t, log.QueryAt).NotEqual((*time.Time)(nil))
		gt.V(t, log.ResponseAt).Equal((*time.Time)(nil))
		gt.A(t, log.Answers).Length(0)
	}

	gt.V(t, tracker.PendingCount()).Equal(0)
}

func TestDNSTracker_FlushEmpty(t *testing.T) {
	tracker := logic.NewDNSTracker()
	logs := tracker.Flush()
	gt.A(t, logs).Length(0)
}

func TestDNSTracker_InputAfterFlush(t *testing.T) {
	tracker := logic.NewDNSTracker()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// Add and flush
	q := buildDNSQueryPacket(t, 0x1111, testClientIP, testServerIP, 10001, testQuestions)
	tracker.Input(q, now)
	tracker.Flush()
	gt.V(t, tracker.PendingCount()).Equal(0)

	// Should work normally after flush
	q2 := buildDNSQueryPacket(t, 0x2222, testClientIP, testServerIP, 10002, testQuestions)
	tracker.Input(q2, now.Add(time.Second))
	gt.V(t, tracker.PendingCount()).Equal(1)

	resp := buildDNSResponsePacket(t, 0x2222, testServerIP, testClientIP, 10002, testQuestions, testAnswers, layers.DNSResponseCodeNoErr)
	logs := tracker.Input(resp, now.Add(2*time.Second))
	gt.A(t, logs).Length(1)
	gt.V(t, logs[0].Status).Equal(model.DNSStatusResolved)
}

func TestDNSTracker_NonDNSPort(t *testing.T) {
	tracker := logic.NewDNSTracker()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	// mDNS packet (port 5353) should be ignored by DNSTracker
	dns := &layers.DNS{
		ID:      0x9999,
		QR:      true,
		ANCount: 1,
		Answers: []layers.DNSResourceRecord{
			{
				Name:  []byte("test.local"),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				IP:    net.IPv4(192, 168, 1, 50),
			},
		},
	}
	pkt := buildPacket(t,
		&layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
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

	logs := tracker.Input(pkt, now)
	gt.A(t, logs).Length(0)
	gt.V(t, tracker.PendingCount()).Equal(0)
}

func TestDNSTracker_ClientServerAddrDirection(t *testing.T) {
	tracker := logic.NewDNSTracker()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	clientIP := net.IPv4(10, 0, 0, 5)
	serverIP := net.IPv4(1, 1, 1, 1)

	// Query: src=client, dst=server
	queryPkt := buildDNSQueryPacket(t, 0xEEEE, clientIP, serverIP, 55555, testQuestions)
	tracker.Input(queryPkt, now)

	// Response: src=server, dst=client
	respPkt := buildDNSResponsePacket(t, 0xEEEE, serverIP, clientIP, 55555, testQuestions, testAnswers, layers.DNSResponseCodeNoErr)
	logs := tracker.Input(respPkt, now.Add(10*time.Millisecond))
	gt.A(t, logs).Length(1)

	// Verify client/server addr are correct
	gt.V(t, logs[0].ClientAddr.String()).Equal(clientIP.String())
	gt.V(t, logs[0].ServerAddr.String()).Equal(serverIP.String())
	gt.V(t, logs[0].ClientPort).Equal(uint32(55555))
	gt.V(t, logs[0].ServerPort).Equal(uint32(53))
}
