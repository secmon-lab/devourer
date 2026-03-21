package logic

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
	"github.com/secmon-lab/devourer/pkg/domain/model"
)

const dnsTimeout = 120 * time.Second

type dnsTransactionKey struct {
	txID       uint16
	clientAddr string // net.IP.String() for map key
	clientPort uint32
	serverAddr string
}

type pendingQuery struct {
	key       dnsTransactionKey
	queryAt   time.Time
	questions []model.DNSQuestion
	serverPort uint32
}

type DNSTracker struct {
	pending map[dnsTransactionKey]*pendingQuery
	mutex   sync.Mutex
}

func NewDNSTracker() *DNSTracker {
	return &DNSTracker{
		pending: make(map[dnsTransactionKey]*pendingQuery),
	}
}

func (t *DNSTracker) Input(pkt gopacket.Packet, now time.Time) []*model.DNSLog {
	dns, ok := getDNSLayer(pkt)
	if !ok {
		return nil
	}

	udpLayer, ok := getUDPLayer(pkt)
	if !ok {
		return nil
	}

	srcPort := uint32(udpLayer.SrcPort)
	dstPort := uint32(udpLayer.DstPort)

	// Only handle standard DNS (port 53)
	if srcPort != 53 && dstPort != 53 {
		return nil
	}

	netLayer := pkt.NetworkLayer()
	if netLayer == nil {
		return nil
	}

	srcAddr := net.IP(netLayer.NetworkFlow().Src().Raw())
	dstAddr := net.IP(netLayer.NetworkFlow().Dst().Raw())

	if dns.QR {
		return t.handleResponse(dns, srcAddr, srcPort, dstAddr, dstPort, now)
	}
	t.handleQuery(dns, srcAddr, srcPort, dstAddr, dstPort, now)
	return nil
}

func (t *DNSTracker) handleQuery(dns *layers.DNS, srcAddr net.IP, srcPort uint32, dstAddr net.IP, dstPort uint32, now time.Time) {
	key := dnsTransactionKey{
		txID:       dns.ID,
		clientAddr: srcAddr.String(),
		clientPort: srcPort,
		serverAddr: dstAddr.String(),
	}

	questions := model.ConvertDNSQuestions(dns.Questions)

	t.mutex.Lock()
	defer t.mutex.Unlock()

	t.pending[key] = &pendingQuery{
		key:        key,
		queryAt:    now,
		questions:  questions,
		serverPort: dstPort,
	}
}

func (t *DNSTracker) handleResponse(dns *layers.DNS, srcAddr net.IP, srcPort uint32, dstAddr net.IP, dstPort uint32, now time.Time) []*model.DNSLog {
	// In a response, src is the server, dst is the client
	key := dnsTransactionKey{
		txID:       dns.ID,
		clientAddr: dstAddr.String(),
		clientPort: dstPort,
		serverAddr: srcAddr.String(),
	}

	questions := model.ConvertDNSQuestions(dns.Questions)
	answers := model.ConvertDNSAnswers(dns.Answers)
	rcode := model.DNSResponseCodeString(dns.ResponseCode)

	t.mutex.Lock()
	defer t.mutex.Unlock()

	if pq, ok := t.pending[key]; ok {
		// Matched: resolved
		delete(t.pending, key)
		queryAt := pq.queryAt
		return []*model.DNSLog{{
			ID:            uuid.New(),
			TransactionID: dns.ID,
			ClientAddr:    net.ParseIP(key.clientAddr),
			ClientPort:    key.clientPort,
			ServerAddr:    srcAddr,
			ServerPort:    srcPort,
			Questions:     pq.questions,
			ResponseCode:  rcode,
			Answers:       answers,
			QueryAt:       &queryAt,
			ResponseAt:    &now,
			Status:        model.DNSStatusResolved,
		}}
	}

	// Unmatched: response_only
	return []*model.DNSLog{{
		ID:            uuid.New(),
		TransactionID: dns.ID,
		ClientAddr:    dstAddr,
		ClientPort:    dstPort,
		ServerAddr:    srcAddr,
		ServerPort:    srcPort,
		Questions:     questions,
		ResponseCode:  rcode,
		Answers:       answers,
		QueryAt:       nil,
		ResponseAt:    &now,
		Status:        model.DNSStatusResponseOnly,
	}}
}

func (t *DNSTracker) Expire(now time.Time) []*model.DNSLog {
	threshold := now.Add(-dnsTimeout)

	t.mutex.Lock()
	defer t.mutex.Unlock()

	var logs []*model.DNSLog
	for key, pq := range t.pending {
		if pq.queryAt.Before(threshold) {
			queryAt := pq.queryAt
			logs = append(logs, &model.DNSLog{
				ID:            uuid.New(),
				TransactionID: key.txID,
				ClientAddr:    net.ParseIP(key.clientAddr),
				ClientPort:    key.clientPort,
				ServerAddr:    net.ParseIP(key.serverAddr),
				ServerPort:    pq.serverPort,
				Questions:     pq.questions,
				ResponseCode:  "",
				Answers:       nil,
				QueryAt:       &queryAt,
				ResponseAt:    nil,
				Status:        model.DNSStatusTimeout,
			})
			delete(t.pending, key)
		}
	}

	return logs
}

func (t *DNSTracker) Flush() []*model.DNSLog {
	t.mutex.Lock()
	defer t.mutex.Unlock()

	var logs []*model.DNSLog
	for key, pq := range t.pending {
		queryAt := pq.queryAt
		logs = append(logs, &model.DNSLog{
			ID:            uuid.New(),
			TransactionID: key.txID,
			ClientAddr:    net.ParseIP(key.clientAddr),
			ClientPort:    key.clientPort,
			ServerAddr:    net.ParseIP(key.serverAddr),
			ServerPort:    pq.serverPort,
			Questions:     pq.questions,
			ResponseCode:  "",
			Answers:       nil,
			QueryAt:       &queryAt,
			ResponseAt:    nil,
			Status:        model.DNSStatusTimeout,
		})
	}
	t.pending = make(map[dnsTransactionKey]*pendingQuery)

	return logs
}

func (t *DNSTracker) PendingCount() int {
	t.mutex.Lock()
	defer t.mutex.Unlock()
	return len(t.pending)
}

// dnsTransactionKey implements fmt.Stringer for debugging
func (k dnsTransactionKey) String() string {
	return fmt.Sprintf("txID=%d client=%s:%d server=%s", k.txID, k.clientAddr, k.clientPort, k.serverAddr)
}
