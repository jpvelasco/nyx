package main

import (
	"os"

	"github.com/velasco-jp/nyx/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(2)
	}
}
