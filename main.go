package main

import (
	"os"

	"github.com/secmon-lab/devourer/pkg/cli"
)

func main() {
	if err := cli.Run(os.Args); err != nil {
		os.Exit(1)
	}
}
