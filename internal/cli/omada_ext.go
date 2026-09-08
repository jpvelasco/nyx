package cli

import (
	"context"
	"fmt"
	"strings"

	providers "github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/spf13/cobra"
)

// omada-specific extra subcommands (observation + plan/apply mutations)
// added on top of the capability-derived commands. They are deliberately
// NOT advertised via Capabilities() — extras stay off the capability
// parity gate (see the CLI/MCP surface split in AGENTS.md). Writes default
// to dry-run, matching the MCP tools.

var (
	omadaUplinkMAC     string
	omadaSwitchPortMAC string
)

// buildOmadaExtraCommands builds the omada-only extra subcommands.
func buildOmadaExtraCommands() []*cobra.Command {
	return []*cobra.Command{
		buildOmadaUplinkInfoCmd(),
		buildOmadaSwitchPortsCmd(),
		buildOmadaLanProfilesCmd(),
		buildOmadaListSSIDsCmd(),
		buildOmadaPlanCmd(),
		buildOmadaApplyACLCmd(),
		buildOmadaPlanPortCmd(),
		buildOmadaApplyPortProfileCmd(),
		buildOmadaPlanLANCmd(),
		buildOmadaApplyLANCmd(),
		buildOmadaPlanSSIDCmd(),
		buildOmadaApplySSIDCmd(),
	}
}

func buildOmadaUplinkInfoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "uplink-info",
		Short: "Show which managed device (and port) a MAC is cabled into",
		RunE: func(_ *cobra.Command, _ []string) error {
			if omadaUplinkMAC == "" {
				return fmt.Errorf("--mac is required: the device MAC to look up")
			}
			return withProviderSession("omada", func(ctx context.Context, opts providers.ImportOptions) error {
				rows, err := service.NewOmadaService().GetUplinkInfo(ctx, toOmadaOptions(opts), []string{omadaUplinkMAC})
				if err != nil {
					return err
				}
				if len(rows) == 0 {
					if jsonOutput {
						return printJSON(map[string]string{"mac": omadaUplinkMAC, "note": "no uplink observed"})
					}
					fmt.Printf("No uplink observed for %s\n", omadaUplinkMAC)
					return nil
				}
				if jsonOutput {
					return printJSON(rows[0])
				}
				r := rows[0]
				fmt.Printf("MAC         : %s\n", r.MAC)
				fmt.Printf("Uplink device: %s (%s)\n", r.UplinkDeviceName, r.UplinkDeviceMAC)
				fmt.Printf("Uplink port : %s\n", r.UplinkDevicePort)
				fmt.Printf("Link speed  : %s (configured; negotiated speed is not on the Open API)\n",
					formatConfiguredLinkSpeed(r.LinkSpeed, r.Duplex))
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&omadaUplinkMAC, "mac", "", "Device MAC to look up (required)")
	addProviderFlags(cmd, "omada")
	return cmd
}

func buildOmadaSwitchPortsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "switch-ports",
		Short: "List switch ports with their live VLAN membership (native + tagged)",
		RunE: func(_ *cobra.Command, _ []string) error {
			return withProviderSession("omada", func(ctx context.Context, opts providers.ImportOptions) error {
				ports, err := service.NewOmadaService().ListSwitchPorts(ctx, toOmadaOptions(opts), omadaSwitchPortMAC)
				if err != nil {
					return err
				}
				if jsonOutput {
					return printJSON(ports)
				}
				fmt.Printf("%-6s %-14s %-8s %-7s %-14s %s\n", "PORT", "SWITCH", "MODE", "NATIVE", "PROFILE", "TAGGED")
				for _, p := range ports {
					mode := "access"
					if p.NetworkMode == 0 {
						mode = "trunk"
					}
					fmt.Printf("%-6d %-14s %-8s %-7s %-14s %s\n",
						p.Port, shortMAC(p.SwitchMAC), mode, p.NativeNetwork, p.ProfileName, joinOrDash(p.Tagged))
				}
				fmt.Println("Note: overview linkSpeed/duplex are configured settings (0=Auto), not negotiated link state.")
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&omadaSwitchPortMAC, "switch-mac", "", "Switch MAC to filter (default: every switch)")
	addProviderFlags(cmd, "omada")
	return cmd
}

func buildOmadaLanProfilesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lan-profiles",
		Short: "List site LAN profiles (native + tagged network membership per profile)",
		RunE: func(_ *cobra.Command, _ []string) error {
			return withProviderSession("omada", func(ctx context.Context, opts providers.ImportOptions) error {
				profiles, err := service.NewOmadaService().ListLanProfiles(ctx, toOmadaOptions(opts))
				if err != nil {
					return err
				}
				if jsonOutput {
					return printJSON(profiles)
				}
				fmt.Printf("%-24s %-14s %s\n", "NAME", "NATIVE", "TAGGED")
				for _, p := range profiles {
					fmt.Printf("%-24s %-14s %s\n", p.Name, p.NativeNetwork, joinOrDash(p.TaggedNetworks))
				}
				return nil
			})
		},
	}
	addProviderFlags(cmd, "omada")
	return cmd
}

func buildOmadaListSSIDsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ssids",
		Short: "List site WLAN groups and SSIDs",
		RunE: func(_ *cobra.Command, _ []string) error {
			return withProviderSession("omada", func(ctx context.Context, opts providers.ImportOptions) error {
				inv, err := service.NewOmadaService().ListSSIDs(ctx, toOmadaOptions(opts))
				if err != nil {
					return err
				}
				if jsonOutput {
					return printJSON(inv)
				}
				fmt.Printf("%-16s %s\n", "GROUP", "ID")
				for _, g := range inv.Groups {
					fmt.Printf("%-16s %s\n", g.Name, g.ID)
				}
				fmt.Printf("%-20s %-20s %-8s %-6s %s\n", "NAME", "SSID", "ENABLED", "VLAN", "SECURITY")
				for _, s := range inv.SSIDs {
					fmt.Printf("%-20s %-20s %-8t %-6d %s\n", s.Name, s.SSID, s.Enabled, s.VLANID, s.Security)
				}
				return nil
			})
		},
	}
	addProviderFlags(cmd, "omada")
	return cmd
}

// toOmadaOptions maps the provider ImportOptions onto the service options.
func toOmadaOptions(opts providers.ImportOptions) service.OmadaOptions {
	return service.OmadaOptions{
		Host:          opts.Host,
		ClientID:      opts.ClientID,
		ClientSecret:  opts.ClientSecret,
		Site:          opts.Site,
		SkipTLSVerify: opts.SkipTLSVerify,
		CACertPath:    opts.CACertPath,
	}
}

// shortMAC renders a MAC for narrow tables: last 4 hex digits.
func shortMAC(mac string) string {
	hex := strings.NewReplacer(":", "", "-", "", " ", "").Replace(mac)
	if len(hex) < 4 {
		return mac
	}
	return "..." + hex[len(hex)-4:]
}

// joinOrDash joins list members with "+", or returns "-" for an empty set.
func joinOrDash(names []string) string {
	if len(names) == 0 {
		return "-"
	}
	out := names[0]
	for _, n := range names[1:] {
		out += "+" + n
	}
	return out
}

// configuredLinkSpeeds / configuredDuplexes are the Open API configured
// setting enums (not negotiated link state). 0 is Auto on both.
var configuredLinkSpeeds = map[int]string{
	0: "Auto", 1: "10M", 2: "100M", 3: "1000M", 4: "2500M", 5: "10G",
}
var configuredDuplexes = map[int]string{
	0: "Auto", 1: "Half", 2: "Full",
}

// formatConfiguredLinkSpeed renders the overview's configured speed/duplex
// pair. Unknown enum values fall back to the raw integer so a future
// controller code is still visible.
func formatConfiguredLinkSpeed(speed, duplex int) string {
	s, ok := configuredLinkSpeeds[speed]
	if !ok {
		s = fmt.Sprintf("%d", speed)
	}
	d, ok := configuredDuplexes[duplex]
	if !ok {
		d = fmt.Sprintf("%d", duplex)
	}
	return s + "/" + d
}
