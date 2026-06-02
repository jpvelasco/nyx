// Package main is the entrypoint for the nyx CLI binary.
package main

import (
	"os"

	"github.com/jpvelasco/nyx/internal/cli"
	_ "github.com/jpvelasco/nyx/internal/providers/omada"
	_ "github.com/jpvelasco/nyx/internal/providers/opnsense"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(2)
	}
}
