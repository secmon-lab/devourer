package model

type Record struct {
	FlowLogs []*Flow
	DNSLogs  []*DNSLog
}
