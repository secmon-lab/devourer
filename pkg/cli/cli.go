package cli

import (
	"context"

	"github.com/secmon-lab/devourer/pkg/cli/config"
	"github.com/secmon-lab/devourer/pkg/domain/types"
	"github.com/secmon-lab/devourer/pkg/utils"
	"github.com/urfave/cli/v3"
)

func Run(args []string) error {
	var (
		logger config.Logger

		closer func()
	)

	cmd := &cli.Command{
		Name:    "devourer",
		Flags:   mergeFlags([]cli.Flag{}, &logger),
		Version: types.AppVersion,
		Commands: []*cli.Command{
			cmdCapture(),
		},
		Before: func(ctx context.Context, cmd *cli.Command) (context.Context, error) {
			f, err := logger.Configure()
			if err != nil {
				return ctx, err
			}
			closer = f
			return ctx, nil
		},
		After: func(ctx context.Context, cmd *cli.Command) error {
			if closer != nil {
				closer()
			}
			return nil
		},
	}

	if err := cmd.Run(context.Background(), args); err != nil {
		utils.Logger().Error("Failed to run devourer", utils.ErrLog(err))
		return err
	}

	return nil
}
