// Package main is the entrypoint for the nyx CLI binary.
package main

import (
	"errors"
	"os"

	"github.com/jpvelasco/nyx/internal/cli"
	_ "github.com/jpvelasco/nyx/internal/providers/omada"
	_ "github.com/jpvelasco/nyx/internal/providers/opnsense"
)

func main() {
	os.Exit(run())
}

// run executes the CLI and returns the process exit code.
// cli.ExitError codes (1/2/3 from check statuses) pass through unchanged;
// any other error maps to the execution-error code 2.
func run() int {
	if err := cli.Execute(); err != nil {
		var ee *cli.ExitError
		if errors.As(err, &ee) {
			return ee.Code
		}
		return 2
	}
	return 0
}
