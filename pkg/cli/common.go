package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/secmon-lab/devourer/pkg/domain/model"
	"github.com/secmon-lab/devourer/pkg/utils"
	"github.com/urfave/cli/v3"
)

type flagConfig interface {
	Flags() []cli.Flag
}

func mergeFlags(base []cli.Flag, configs ...flagConfig) []cli.Flag {
	ret := base[:]
	for _, config := range configs {
		ret = append(ret, config.Flags()...)
	}

	return ret
}

type jsonDumper struct {
	encoder *json.Encoder
	closer  io.Closer
}

func (s *jsonDumper) Dump(ctx context.Context, record *model.Record) error {
	for _, flow := range record.FlowLogs {
		if err := s.encoder.Encode(flow); err != nil {
			return err
		}
	}
	for _, dl := range record.DNSLogs {
		if err := s.encoder.Encode(dl); err != nil {
			return err
		}
	}

	return nil
}

func (s *jsonDumper) Close() {
	if s.closer != nil {
		utils.SafeClose(s.closer)
	}
}

func convertToBps(bytes float64) string {
	bytes = bytes * 8
	units := []string{"bps", "Kbps", "Mbps", "Gbps", "Tbps", "Pbps", "Ebps"}

	unitIndex := 0
	for bytes >= 1024 && unitIndex < len(units)-1 {
		bytes /= 1024
		unitIndex++
	}

	return fmt.Sprintf("%.2f %s", bytes, units[unitIndex])
}
