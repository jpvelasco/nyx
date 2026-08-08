// Package main is the entrypoint for the nyx CLI binary.
package main

import (
	"os"

	"github.com/jpvelasco/nyx/internal/cli"
	_ "github.com/jpvelasco/nyx/internal/providers/omada"
	_ "github.com/jpvelasco/nyx/internal/providers/opnsense"
)

func main() {
	os.Exit(run())
}

// run executes the CLI and returns the process exit code.
func run() int {
	if err := cli.Execute(); err != nil {
		return 2
	}
	return 0
}
