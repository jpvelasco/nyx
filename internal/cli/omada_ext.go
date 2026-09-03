package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	providers "github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/spf13/cobra"
)

// omada-specific observation subcommands (uplink-info, switch-ports,
// lan-profiles) added on top of the capability-derived commands. They are
// deliberately NOT advertised via Capabilities() — the same exemption as
// the MCP-only plan/apply tools (see the CLI/MCP surface split in
// AGENTS.md).

var (
	omadaUplinkMAC     string
	omadaSwitchPortMAC string
)

// buildOmadaExtraCommands builds the omada-only observation subcommands.
func buildOmadaExtraCommands() []*cobra.Command {
	return []*cobra.Command{
		buildOmadaUplinkInfoCmd(),
		buildOmadaSwitchPortsCmd(),
		buildOmadaLanProfilesCmd(),
	}
}

func buildOmadaUplinkInfoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "uplink-info",
		Short: "Show which managed device (and port) a MAC is cabled into",
		RunE: func(_ *cobra.Command, _ []string) error {
			dur, err := parseTimeoutFlag(timeout)
			if err != nil {
				return err
			}
			if dur == 0 {
				dur = 60 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), dur)
			defer cancel()

			if omadaUplinkMAC == "" {
				return fmt.Errorf("--mac is required: the device MAC to look up")
			}
			opts := providerImportOptions("omada")
			if err := requireProviderHost(opts, "omada"); err != nil {
				return err
			}
			rows, err := service.NewOmadaService().GetUplinkInfo(ctx, toOmadaOptions(opts), []string{omadaUplinkMAC})
			if err != nil {
				return err
			}
			if len(rows) == 0 {
				if jsonOutput {
					enc := json.NewEncoder(os.Stdout)
					enc.SetIndent("", "  ")
					return enc.Encode(map[string]string{"mac": omadaUplinkMAC, "note": "no uplink observed"})
				}
				fmt.Printf("No uplink observed for %s\n", omadaUplinkMAC)
				return nil
			}
			if jsonOutput {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(rows[0])
			}
			r := rows[0]
			fmt.Printf("MAC         : %s\n", r.MAC)
			fmt.Printf("Uplink device: %s (%s)\n", r.UplinkDeviceName, r.UplinkDeviceMAC)
			fmt.Printf("Uplink port : %s\n", r.UplinkDevicePort)
			return nil
		},
	}
	cmd.Flags().StringVar(&omadaUplinkMAC, "mac", "", "Device MAC to look up (required)")
	addProviderFlags(cmd)
	return cmd
}

func buildOmadaSwitchPortsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "switch-ports",
		Short: "List switch ports with their live VLAN membership (native + tagged)",
		RunE: func(_ *cobra.Command, _ []string) error {
			dur, err := parseTimeoutFlag(timeout)
			if err != nil {
				return err
			}
			if dur == 0 {
				dur = 60 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), dur)
			defer cancel()

			opts := providerImportOptions("omada")
			if err := requireProviderHost(opts, "omada"); err != nil {
				return err
			}
			ports, err := service.NewOmadaService().ListSwitchPorts(ctx, toOmadaOptions(opts), omadaSwitchPortMAC)
			if err != nil {
				return err
			}
			if jsonOutput {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(ports)
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
			return nil
		},
	}
	cmd.Flags().StringVar(&omadaSwitchPortMAC, "switch-mac", "", "Switch MAC to filter (default: every switch)")
	addProviderFlags(cmd)
	return cmd
}

func buildOmadaLanProfilesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "lan-profiles",
		Short: "List site LAN profiles (native + tagged network membership per profile)",
		RunE: func(_ *cobra.Command, _ []string) error {
			dur, err := parseTimeoutFlag(timeout)
			if err != nil {
				return err
			}
			if dur == 0 {
				dur = 60 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), dur)
			defer cancel()

			opts := providerImportOptions("omada")
			if err := requireProviderHost(opts, "omada"); err != nil {
				return err
			}
			profiles, err := service.NewOmadaService().ListLanProfiles(ctx, toOmadaOptions(opts))
			if err != nil {
				return err
			}
			if jsonOutput {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(profiles)
			}
			fmt.Printf("%-24s %-14s %s\n", "NAME", "NATIVE", "TAGGED")
			for _, p := range profiles {
				fmt.Printf("%-24s %-14s %s\n", p.Name, p.NativeNetwork, joinOrDash(p.TaggedNetworks))
			}
			return nil
		},
	}
	addProviderFlags(cmd)
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
	if len(mac) < 4 {
		return mac
	}
	return "..." + mac[len(mac)-4:]
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
