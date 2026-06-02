package cli

import (
	"fmt"
	"net"

	"github.com/jpvelasco/nyx/internal/backends/system"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/spf13/cobra"
)

var listInterfacesCmd = &cobra.Command{
	Use:   "interfaces",
	Short: "List available network interfaces on this machine",
	Long: `List all active (non-loopback) network interfaces with their addresses.
Useful for discovering the exact name to pass to --interface.
When --spec is provided, highlights interfaces that match your spec networks.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		ctx := cmd.Context()

		ifaces, err := system.GetInterfaces(ctx)
		if err != nil {
			return fmt.Errorf("listing interfaces: %w", err)
		}

		if len(ifaces) == 0 {
			fmt.Println("No active network interfaces found.")
			return nil
		}

		// Build spec network map if --spec is provided
		var specNetworks []specNetwork
		if specFile != "" {
			spec, err := intent.LoadSpec(specFile)
			if err != nil {
				return fmt.Errorf("loading spec: %w", err)
			}
			for _, n := range spec.Networks {
				_, cidr, err := net.ParseCIDR(n.CIDR)
				if err != nil {
					continue
				}
				specNetworks = append(specNetworks, specNetwork{name: n.Name, cidr: cidr})
			}
		}

		fmt.Println("Available network interfaces:")
		hasSpec := len(specNetworks) > 0
		for _, iface := range ifaces {
			fmt.Printf("  - %s", iface.Name)
			if iface.Type != "" {
				fmt.Printf(" (%s)", iface.Type)
			}
			fmt.Println()

			for _, addr := range iface.Addrs {
				fmt.Printf("      %s", addr)
				if hasSpec {
					// Check if this address falls inside any spec network
					if ipnet, ok := parseIPNet(addr); ok {
						for _, sn := range specNetworks {
							if sn.cidr.Contains(ipnet.IP) {
								fmt.Printf("  ← %s", sn.name)
								break
							}
						}
					}
				}
				fmt.Println()
			}
		}

		fmt.Println("\nUse --interface <name> (exact name) to force nyx to use a specific adapter.")
		if hasSpec {
			fmt.Println("  ← marks the interface that matches your spec. That's the one to use with --interface.")
		}
		return nil
	},
}

type specNetwork struct {
	name string
	cidr *net.IPNet
}

func parseIPNet(addr string) (*net.IPNet, bool) {
	if ipnet, ok := parseAsIPNet(addr); ok {
		return ipnet, true
	}
	// Try appending /32 for bare IP
	if ipnet, ok := parseAsIPNet(addr + "/32"); ok {
		return ipnet, true
	}
	return nil, false
}

func parseAsIPNet(s string) (*net.IPNet, bool) {
	ip, cidr, err := net.ParseCIDR(s)
	if err != nil {
		return nil, false
	}
	return &net.IPNet{IP: ip, Mask: cidr.Mask}, true
}

func init() {
	rootCmd.AddCommand(listInterfacesCmd)
}
