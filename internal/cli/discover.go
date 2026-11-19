package cli

import (
	"context"
	"fmt"

	"github.com/jpvelasco/nyx/internal/backends/nmap"
	"github.com/jpvelasco/nyx/internal/report"
	"github.com/spf13/cobra"
)

var (
	discoverSubnet  string
	discoverProbes  string
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
	RunE: func(cmd *cobra.Command, _ []string) error {
		if discoverSubnet == "" {
			return fmt.Errorf("--subnet is required")
		}

		probeSet, err := resolveDiscoverProbeSet(discoverProbes, discoverSubnet)
		if err != nil {
			return err
		}

		if err := nmap.CheckAvailable(); err != nil {
			return err
		}

		dur, err := parseTimeoutFlag(timeout)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), dur)
		defer cancel()

		timing, minRate := pacingFor(probeSet, discoverTiming, discoverMinRate,
			cmd.Flags().Changed("timing"), cmd.Flags().Changed("min-rate"))

		opts := nmap.ScanOptions{
			TimingTemplate: timing,
			MinRate:        minRate,
			ProbeSet:       probeSet,
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

// pacingFor returns the nmap timing template and min rate to use. Routed
// (ICMP) sweeps send IP probes at the gateway, so they keep the polite
// preset by default; the user opts in to the aggressive defaults with
// explicit --timing / --min-rate flags.
func pacingFor(probeSet nmap.ProbeSet, timing, minRate int, timingChanged, minRateChanged bool) (int, int) {
	if probeSet == nmap.ProbeSetICMP && !timingChanged && !minRateChanged {
		return nmap.PoliteScanOptions.TimingTemplate, nmap.PoliteScanOptions.MinRate
	}
	return timing, minRate
}

// resolveDiscoverProbeSet maps the --probes flag to a ProbeSet. "auto"
// selects ARP for directly-attached subnets and ICMP echo for routed ones.
func resolveDiscoverProbeSet(probes, cidr string) (nmap.ProbeSet, error) {
	if probes == "auto" {
		return nmap.ChooseProbeSet(cidr)
	}
	probeSet, err := nmap.ParseProbeSet(probes)
	if err != nil {
		return nmap.ProbeSetDefault, err
	}
	if probeSet == nmap.ProbeSetARP {
		attached, err := nmap.DirectlyAttached(cidr)
		if err != nil {
			return nmap.ProbeSetDefault, err
		}
		if !attached {
			return nmap.ProbeSetDefault, fmt.Errorf("ARP ping only works on directly-attached subnets — %s is not attached to a local interface; use --probes icmp or auto", cidr)
		}
	}
	return probeSet, nil
}

func init() {
	discoverCmd.Flags().StringVar(&discoverSubnet, "subnet", "", "CIDR subnet to scan (e.g. 10.0.20.0/24)")
	discoverCmd.Flags().StringVar(&discoverProbes, "probes", "auto", "Host-discovery probes: auto, arp (directly-attached only), icmp, or default")
	discoverCmd.Flags().IntVar(&discoverTiming, "timing", nmap.DefaultScanOptions.TimingTemplate, "nmap timing template (0-5, higher = faster)")
	discoverCmd.Flags().IntVar(&discoverMinRate, "min-rate", nmap.DefaultScanOptions.MinRate, "nmap minimum packet rate (packets/sec)")
}
