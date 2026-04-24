package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/velasco-jp/netaudit/internal/backends/nmap"
	"github.com/velasco-jp/netaudit/internal/report"
)

var (
	discoverSubnet string
)

var discoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Discover hosts and services in a subnet",
	Long:  "Discover active hosts in a subnet using nmap ping sweep.",
	Example: `  netaudit discover --subnet 10.0.20.0/24
  netaudit discover --subnet 10.0.20.0/24 --json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if discoverSubnet == "" {
			return fmt.Errorf("--subnet is required")
		}

		if err := nmap.CheckAvailable(); err != nil {
			return err
		}

		dur, err := time.ParseDuration(timeout)
		if err != nil {
			dur = 60 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), dur)
		defer cancel()

		result, err := nmap.Discover(ctx, discoverSubnet)
		if err != nil {
			return fmt.Errorf("discovery failed: %w", err)
		}

		w := getWriter()
		if w != os.Stdout {
			defer w.Close()
		}

		if jsonOutput {
			return report.RenderResultJSON(w, result)
		}
		report.RenderResultHuman(w, result)
		return nil
	},
}

func init() {
	discoverCmd.Flags().StringVar(&discoverSubnet, "subnet", "", "CIDR subnet to scan (e.g. 10.0.20.0/24)")
}
