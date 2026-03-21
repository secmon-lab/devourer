package bq

import (
	"context"
	"net"
	"time"

	"cloud.google.com/go/bigquery"
	"github.com/secmon-lab/devourer/pkg/domain/interfaces"
	"github.com/secmon-lab/devourer/pkg/domain/model"
	"github.com/secmon-lab/devourer/pkg/utils"
	"github.com/m-mizutani/goerr/v2"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

type implClient struct {
	projectID string
	datasetID string
	client    *bigquery.Client
	dataSet   *bigquery.Dataset
}

type bqDNSLog struct {
	ID            string          `bigquery:"id"`
	TransactionID int64           `bigquery:"tx_id"`
	ClientAddr    string          `bigquery:"client_addr"`
	ClientPort    int             `bigquery:"client_port"`
	ServerAddr    string          `bigquery:"server_addr"`
	ServerPort    int             `bigquery:"server_port"`
	Questions     []bqDNSQuestion `bigquery:"questions"`
	ResponseCode  string          `bigquery:"response_code"`
	Answers       []bqDNSAnswer   `bigquery:"answers"`
	QueryAt       bigquery.NullTimestamp `bigquery:"query_at"`
	ResponseAt    bigquery.NullTimestamp `bigquery:"response_at"`
	Status        string          `bigquery:"status"`
}

type bqDNSQuestion struct {
	Name string `bigquery:"name"`
	Type string `bigquery:"type"`
}

type bqDNSAnswer struct {
	Name  string `bigquery:"name"`
	Type  string `bigquery:"type"`
	Value string `bigquery:"value"`
	TTL   int64  `bigquery:"ttl"`
}

type flowLog struct {
	ID          string    `bigquery:"id"`
	Protocol    string    `bigquery:"protocol"`
	SrcAddr     string    `bigquery:"src_addr"`
	DstAddr     string    `bigquery:"dst_addr"`
	SrcPort     int       `bigquery:"src_port"`
	DstPort     int       `bigquery:"dst_port"`
	SrcHWAddr   string    `bigquery:"src_hw_addr"`
	DstHWAddr   string    `bigquery:"dst_hw_addr"`
	SrcNames    []string  `bigquery:"src_names"`
	DstNames    []string  `bigquery:"dst_names"`
	FirstSeenAt time.Time `bigquery:"first_seen_at"`
	LastSeenAt  time.Time `bigquery:"last_seen_at"`
	SrcBytes    int64     `bigquery:"src_bytes"`
	DstBytes    int64     `bigquery:"dst_bytes"`
	SrcPackets  int64     `bigquery:"src_packets"`
	DstPackets  int64     `bigquery:"dst_packets"`
	Status      string    `bigquery:"status"`
}

const (
	tblFlowLogs = "flow_logs"
	tblDNSLogs  = "dns_logs"
)

func New(ctx context.Context, projectID, datasetID string, opts ...option.ClientOption) (interfaces.Dumper, error) {
	bqClient, err := bigquery.NewClient(ctx, projectID, opts...)
	if err != nil {
		return nil, err
	}

	dataSet := bqClient.Dataset(datasetID)

	tables := []struct {
		name           string
		schema         any
		partitionField string
	}{
		{
			name:           tblFlowLogs,
			schema:         flowLog{},
			partitionField: "first_seen_at",
		},
		{
			name:           tblDNSLogs,
			schema:         bqDNSLog{},
			partitionField: "query_at",
		},
	}

	for _, t := range tables {
		table := dataSet.Table(t.name)
		schema, err := bigquery.InferSchema(t.schema)
		if err != nil {
			return nil, goerr.Wrap(err, "failed to infer schema", goerr.Value("table", t.name))
		}

		meta := &bigquery.TableMetadata{
			Schema: schema,
			TimePartitioning: &bigquery.TimePartitioning{
				Type:  bigquery.DayPartitioningType,
				Field: t.partitionField,
			},
		}
		if err := table.Create(ctx, meta); err != nil {
			if gerr, ok := err.(*googleapi.Error); !ok || gerr.Code != 409 {
				return nil, goerr.Wrap(err, "failed to create table", goerr.Value("table", t.name))
			}
		}
	}

	return &implClient{
		projectID: projectID,
		datasetID: datasetID,
		client:    bqClient,
		dataSet:   dataSet,
	}, nil
}

func (x *implClient) Dump(ctx context.Context, record *model.Record) error {
	if len(record.FlowLogs) > 0 {
		rows := make([]flowLog, len(record.FlowLogs))
		for i, flow := range record.FlowLogs {
			rows[i] = flowLog{
				ID:          flow.ID.String(),
				Protocol:    flow.Protocol,
				SrcAddr:     flow.Src.Addr.String(),
				DstAddr:     flow.Dst.Addr.String(),
				SrcPort:     int(flow.Src.Port),
				DstPort:     int(flow.Dst.Port),
				SrcHWAddr:   hwAddrString(flow.Src.HWAddr),
				DstHWAddr:   hwAddrString(flow.Dst.HWAddr),
				SrcNames:    flow.Src.Names,
				DstNames:    flow.Dst.Names,
				FirstSeenAt: flow.FirstSeenAt,
				LastSeenAt:  flow.LastSeenAt,
				SrcBytes:    int64(flow.SrcStat.Bytes),
				DstBytes:    int64(flow.DstStat.Bytes),
				SrcPackets:  int64(flow.SrcStat.Packets),
				DstPackets:  int64(flow.DstStat.Packets),
				Status:      flow.Status,
			}
		}

		insert := x.dataSet.Table(tblFlowLogs).Inserter()
		if err := insert.Put(ctx, rows); err != nil {
			return goerr.Wrap(err, "failed to insert row of new flows")
		}
	}

	if len(record.DNSLogs) > 0 {
		rows := make([]bqDNSLog, len(record.DNSLogs))
		for i, dl := range record.DNSLogs {
			questions := make([]bqDNSQuestion, len(dl.Questions))
			for j, q := range dl.Questions {
				questions[j] = bqDNSQuestion{Name: q.Name, Type: q.Type}
			}
			answers := make([]bqDNSAnswer, len(dl.Answers))
			for j, a := range dl.Answers {
				answers[j] = bqDNSAnswer{Name: a.Name, Type: a.Type, Value: a.Value, TTL: a.TTL}
			}

			rows[i] = bqDNSLog{
				ID:            dl.ID.String(),
				TransactionID: int64(dl.TransactionID),
				ClientAddr:    dl.ClientAddr.String(),
				ClientPort:    int(dl.ClientPort),
				ServerAddr:    dl.ServerAddr.String(),
				ServerPort:    int(dl.ServerPort),
				Questions:     questions,
				ResponseCode:  dl.ResponseCode,
				Answers:       answers,
				Status:        dl.Status,
			}

			if dl.QueryAt != nil {
				rows[i].QueryAt = bigquery.NullTimestamp{Timestamp: *dl.QueryAt, Valid: true}
			}
			if dl.ResponseAt != nil {
				rows[i].ResponseAt = bigquery.NullTimestamp{Timestamp: *dl.ResponseAt, Valid: true}
			}
		}

		insert := x.dataSet.Table(tblDNSLogs).Inserter()
		if err := insert.Put(ctx, rows); err != nil {
			return goerr.Wrap(err, "failed to insert DNS logs")
		}
	}

	return nil
}

func hwAddrString(addr net.HardwareAddr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

func (x *implClient) Close() {
	utils.SafeClose(x.client)
}
