package main

import (
	"os"

	"github.com/velasco-jp/nyx/internal/cli"
	_ "github.com/velasco-jp/nyx/internal/providers/omada"
	_ "github.com/velasco-jp/nyx/internal/providers/opnsense"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(2)
	}
}
