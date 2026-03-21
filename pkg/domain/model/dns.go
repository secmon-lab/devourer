package model

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/uuid"
)

const (
	DNSStatusResolved     = "resolved"
	DNSStatusTimeout      = "timeout"
	DNSStatusResponseOnly = "response_only"
)

type DNSLog struct {
	ID            uuid.UUID    `json:"id"`
	TransactionID uint16       `json:"tx_id"`
	ClientAddr    net.IP       `json:"client_addr"`
	ClientPort    uint32       `json:"client_port"`
	ServerAddr    net.IP       `json:"server_addr"`
	ServerPort    uint32       `json:"server_port"`
	Questions     []DNSQuestion `json:"questions"`
	ResponseCode  string       `json:"response_code"`
	Answers       []DNSAnswer  `json:"answers"`
	QueryAt       *time.Time   `json:"query_at"`
	ResponseAt    *time.Time   `json:"response_at"`
	Status        string       `json:"status"`
}

type DNSQuestion struct {
	Name string `json:"name" bigquery:"name"`
	Type string `json:"type" bigquery:"type"`
}

type DNSAnswer struct {
	Name  string `json:"name" bigquery:"name"`
	Type  string `json:"type" bigquery:"type"`
	Value string `json:"value" bigquery:"value"`
	TTL   int64  `json:"ttl" bigquery:"ttl"`
}

func ConvertDNSQuestions(questions []layers.DNSQuestion) []DNSQuestion {
	result := make([]DNSQuestion, len(questions))
	for i, q := range questions {
		result[i] = DNSQuestion{
			Name: normalizeDNSName(string(q.Name)),
			Type: q.Type.String(),
		}
	}
	return result
}

func ConvertDNSAnswers(answers []layers.DNSResourceRecord) []DNSAnswer {
	result := make([]DNSAnswer, 0, len(answers))
	for _, a := range answers {
		answer := DNSAnswer{
			Name: normalizeDNSName(string(a.Name)),
			Type: a.Type.String(),
			TTL:  int64(a.TTL),
		}

		switch a.Type {
		case layers.DNSTypeA, layers.DNSTypeAAAA:
			if a.IP != nil {
				answer.Value = a.IP.String()
			}
		case layers.DNSTypeCNAME:
			answer.Value = normalizeDNSName(string(a.CNAME))
		case layers.DNSTypeNS:
			answer.Value = normalizeDNSName(string(a.NS))
		case layers.DNSTypePTR:
			answer.Value = normalizeDNSName(string(a.PTR))
		case layers.DNSTypeMX:
			answer.Value = fmt.Sprintf("%d %s", a.MX.Preference, normalizeDNSName(string(a.MX.Name)))
		case layers.DNSTypeTXT:
			parts := make([]string, len(a.TXTs))
			for i, txt := range a.TXTs {
				parts[i] = string(txt)
			}
			answer.Value = strings.Join(parts, "")
		case layers.DNSTypeSRV:
			answer.Value = fmt.Sprintf("%d %d %d %s",
				a.SRV.Priority, a.SRV.Weight, a.SRV.Port,
				normalizeDNSName(string(a.SRV.Name)))
		case layers.DNSTypeSOA:
			answer.Value = fmt.Sprintf("%s %s %d %d %d %d %d",
				normalizeDNSName(string(a.SOA.MName)),
				normalizeDNSName(string(a.SOA.RName)),
				a.SOA.Serial, a.SOA.Refresh, a.SOA.Retry,
				a.SOA.Expire, a.SOA.Minimum)
		default:
			answer.Value = fmt.Sprintf("%x", a.Data)
		}

		result = append(result, answer)
	}
	return result
}

func normalizeDNSName(name string) string {
	return strings.TrimSuffix(name, ".")
}

var dnsRCodeNames = map[layers.DNSResponseCode]string{
	layers.DNSResponseCodeNoErr:    "NOERROR",
	layers.DNSResponseCodeFormErr:  "FORMERR",
	layers.DNSResponseCodeServFail: "SERVFAIL",
	layers.DNSResponseCodeNXDomain: "NXDOMAIN",
	layers.DNSResponseCodeNotImp:   "NOTIMP",
	layers.DNSResponseCodeRefused:  "REFUSED",
}

func DNSResponseCodeString(code layers.DNSResponseCode) string {
	if name, ok := dnsRCodeNames[code]; ok {
		return name
	}
	return fmt.Sprintf("RCODE%d", code)
}
