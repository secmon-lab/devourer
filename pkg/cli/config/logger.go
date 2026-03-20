package config

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/m-mizutani/clog"
	"github.com/m-mizutani/goerr/v2"
	"github.com/m-mizutani/masq"
	"github.com/secmon-lab/devourer/pkg/domain/types"
	"github.com/secmon-lab/devourer/pkg/utils"
	"github.com/urfave/cli/v3"
)

type Logger struct {
	level  string
	format string
	output string
}

func (x *Logger) Flags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "log-level",
			Category:    "logging",
			Aliases:     []string{"l"},
			Sources:     cli.EnvVars("DEVOURER_LOG_LEVEL"),
			Usage:       "Set log level [debug|info|warn|error]",
			Value:       "info",
			Destination: &x.level,
		},
		&cli.StringFlag{
			Name:        "log-format",
			Category:    "logging",
			Aliases:     []string{"f"},
			Sources:     cli.EnvVars("DEVOURER_LOG_FORMAT"),
			Usage:       "Set log format [console|json]",
			Value:       "console",
			Destination: &x.format,
		},
		&cli.StringFlag{
			Name:        "log-output",
			Category:    "logging",
			Aliases:     []string{"o"},
			Sources:     cli.EnvVars("DEVOURER_LOG_OUTPUT"),
			Usage:       "Set log output (create file other than '-', 'stdout', 'stderr')",
			Value:       "stderr",
			Destination: &x.output,
		},
	}
}

type logFormat int

const (
	logFormatConsole logFormat = iota + 1
	logFormatJSON
)

// Configure sets up logger and returns closer function and error. You can call closer even if error is not nil.
func (x *Logger) Configure() (func(), error) {
	closer := func() {}
	formatMap := map[string]logFormat{
		"console": logFormatConsole,
		"json":    logFormatJSON,
	}
	format, ok := formatMap[x.format]
	if !ok {
		return closer, goerr.Wrap(types.ErrInvalidOption, "Invalid log format", goerr.Value("format", x.format))
	}

	levelMap := map[string]slog.Level{
		"debug": slog.LevelDebug,
		"info":  slog.LevelInfo,
		"warn":  slog.LevelWarn,
		"error": slog.LevelError,
	}
	level, ok := levelMap[x.level]
	if !ok {
		return closer, goerr.Wrap(types.ErrInvalidOption, "Invalid log level", goerr.Value("level", x.level))
	}

	var output io.Writer
	switch x.output {
	case "stdout", "-":
		output = os.Stdout
	case "stderr":
		output = os.Stderr
	default:
		f, err := os.OpenFile(filepath.Clean(x.output), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			return closer, goerr.Wrap(err, "Failed to open log file", goerr.Value("path", x.output))
		}
		output = f
		closer = func() {
			utils.SafeClose(f)
		}
	}

	filter := masq.New(
		masq.WithTag("secret"),
	)

	var handler slog.Handler
	switch format {
	case logFormatConsole:
		handler = clog.New(
			clog.WithWriter(output),
			clog.WithLevel(level),
			clog.WithReplaceAttr(filter),
			clog.WithSource(true),
			clog.WithColorMap(&clog.ColorMap{
				Level: map[slog.Level]*color.Color{
					slog.LevelDebug: color.New(color.FgGreen, color.Bold),
					slog.LevelInfo:  color.New(color.FgCyan, color.Bold),
					slog.LevelWarn:  color.New(color.FgYellow, color.Bold),
					slog.LevelError: color.New(color.FgRed, color.Bold),
				},
				LevelDefault: color.New(color.FgBlue, color.Bold),
				Time:         color.New(color.FgWhite),
				Message:      color.New(color.FgHiWhite),
				AttrKey:      color.New(color.FgHiCyan),
				AttrValue:    color.New(color.FgHiWhite),
			}),
		)

	case logFormatJSON:
		handler = slog.NewJSONHandler(output, &slog.HandlerOptions{
			AddSource:   true,
			Level:       level,
			ReplaceAttr: filter,
		})

	default:
		panic("Unsupported log format: " + fmt.Sprintf("%d", format))
	}

	utils.ReconfigureLogger(handler)

	return closer, nil
}
