package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/jpvelasco/nyx/internal/backends/nmap"
	"github.com/jpvelasco/nyx/internal/report"
	"github.com/spf13/cobra"
)

var (
	discoverSubnet  string
	discoverTiming  int
	discoverMinRate int
)

var discoverCmd = &cobra.Command{
	Use:   "discover",
	Short: "Discover hosts and services in a subnet",
	Long:  "Discover active hosts in a subnet using nmap ping sweep.",
	Example: `  nyx discover --subnet 10.0.20.0/24
  nyx discover --subnet 10.0.20.0/24 --json
  nyx discover --subnet 10.0.20.0/24 --timing 3 --min-rate 200`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if discoverSubnet == "" {
			return fmt.Errorf("--subnet is required")
		}

		if err := nmap.CheckAvailable(); err != nil {
			return err
		}

		dur, err := time.ParseDuration(timeout)
		if err != nil {
			dur = 90 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), dur)
		defer cancel()

		opts := nmap.ScanOptions{
			TimingTemplate: discoverTiming,
			MinRate:        discoverMinRate,
		}
		result, err := nmap.DiscoverWithOptions(ctx, discoverSubnet, opts)
		if err != nil {
			return fmt.Errorf("discovery failed: %w", err)
		}

		w, err := getWriter()
		if err != nil {
			return err
		}
		if outputPath != "" {
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
	discoverCmd.Flags().IntVar(&discoverTiming, "timing", nmap.DefaultScanOptions.TimingTemplate, "nmap timing template (0-5, higher = faster)")
	discoverCmd.Flags().IntVar(&discoverMinRate, "min-rate", nmap.DefaultScanOptions.MinRate, "nmap minimum packet rate (packets/sec)")
}
