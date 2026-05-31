package cli

import (
	"fmt"
	"net"
	"strings"

	"github.com/velasco-jp/nyx/internal/intent"
	"github.com/velasco-jp/nyx/internal/models"
)

// EnvironmentBriefing contains a friendly summary of the current machine's network situation.
// This is the "I just landed, let me tell you what I see" experience.
type EnvironmentBriefing struct {
	ActiveInterfaces []string
	CurrentIPs       []string
	MatchedNetworks  []string // networks from the spec that this machine appears to be inside
	MultiHomed       bool
	InterfaceCount   int
	Summary          string // Human-friendly one-liner or short paragraph
	Recommendations  []string
}

// GetEnvironmentBriefing builds a helpful "I just landed" summary.
// If a spec is provided, it will try to match current interfaces against the declared networks.
func GetEnvironmentBriefing(spec *intent.Spec) EnvironmentBriefing {
	brief := EnvironmentBriefing{}

	ifaces, err := net.Interfaces()
	if err != nil {
		brief.Summary = "Unable to enumerate network interfaces."
		return brief
	}

	var active []string
	var ips []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		hasIPv4 := false
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				ips = append(ips, ipnet.IP.String())
				hasIPv4 = true
			}
		}
		if hasIPv4 {
			active = append(active, iface.Name)
		}
	}

	brief.ActiveInterfaces = active
	brief.CurrentIPs = ips
	brief.InterfaceCount = len(active)

	// Match against spec if provided
	hasSpec := spec != nil
	if spec != nil {
		selectedIface := GetSelectedInterface()
		runner := getCurrentRunnerContext(spec, selectedIface)
		brief.MatchedNetworks = runner.Networks
	}

	brief.MultiHomed = len(active) > 1

	// Build the "I just landed" narrative
	if len(active) == 0 {
		brief.Summary = "Nothing to connect through — no active network interfaces found. Are you plugged in?"
	} else if brief.MultiHomed {
		brief.Summary = fmt.Sprintf("You're multi-homed — I see %d active interfaces: %s.", len(active), strings.Join(active, ", "))
		if len(brief.MatchedNetworks) > 0 {
			brief.Summary += fmt.Sprintf(" That puts you inside: %s.", strings.Join(brief.MatchedNetworks, ", "))
		} else if hasSpec {
			brief.Summary += " But none of those IPs match a network in your spec — we're in uncharted territory."
		}
		brief.Recommendations = append(brief.Recommendations, "Since you're on multiple networks at once, use --interface to pick which one I should run checks from. (Run 'nyx interfaces' to see the list.)")
	} else {
		brief.Summary = fmt.Sprintf("You're on a single interface: %s", active[0])
		if len(brief.MatchedNetworks) > 0 {
			brief.Summary += fmt.Sprintf(" — that's inside: %s.", strings.Join(brief.MatchedNetworks, ", "))
		} else if hasSpec {
			brief.Summary += ". I don't see that matching any network in your spec."
		}
	}

	return brief
}

// getCurrentRunnerContext builds runner context using the same selection rules as the rest of nyx.
// This keeps the First Contact experience consistent with --interface behavior.
func getCurrentRunnerContext(spec *intent.Spec, interfaceName string) models.RunnerContext {
	ifaces, _ := net.Interfaces()
	var localIPStrs []string
	var matched []string

	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if interfaceName != "" && iface.Name != interfaceName {
			continue
		}

		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				localIPStrs = append(localIPStrs, ipnet.IP.String())
				if spec != nil {
					for _, n := range spec.Networks {
						_, cidr, err := net.ParseCIDR(n.CIDR)
						if err == nil && cidr.Contains(ipnet.IP) {
							matched = append(matched, n.Name)
						}
					}
				}
			}
		}
	}

	return models.RunnerContext{
		LocalIPs: localIPStrs,
		Networks: matched,
	}
}

// RenderEnvironmentBriefing returns a friendly multi-line string suitable for human output.
// This is the "I just landed" narrative — warm, oriented, not clinical.
func RenderEnvironmentBriefing(b EnvironmentBriefing) string {
	var sb strings.Builder

	sb.WriteString("--- Where We Are ---\n")
	sb.WriteString(b.Summary)

	// Show IPs next to interfaces so the user can actually orient themselves
	if len(b.CurrentIPs) > 0 && len(b.ActiveInterfaces) > 0 {
		ifacesWithIPs := mapIfaceToIP(b.ActiveInterfaces, b.CurrentIPs)
		sb.WriteString("\n")
		for name, ifaceIPs := range ifacesWithIPs {
			sb.WriteString(fmt.Sprintf("  %s → %s\n", name, strings.Join(ifaceIPs, ", ")))
		}
	}

	if len(b.MatchedNetworks) > 0 {
		sb.WriteString(fmt.Sprintf("\n  Your spec declares those as: %s\n", strings.Join(b.MatchedNetworks, ", ")))
	}

	if len(b.Recommendations) > 0 {
		sb.WriteString("\n")
		for _, r := range b.Recommendations {
			sb.WriteString(fmt.Sprintf("  → %s\n", r))
		}
	}

	sb.WriteString("\n")
	return sb.String()
}

// mapIfaceToIP tries to pair each interface with the IPs it holds.
// Since the brief doesn't carry the raw iface→IP mapping, we infer by
// checking the actual system state (same logic as GetEnvironmentBriefing).
func mapIfaceToIP(interfaces, ips []string) map[string][]string {
	result := map[string][]string{}
	ifaces, _ := net.Interfaces()
	for _, iface := range ifaces {
		// Only include interfaces from the brief
		inBrief := false
		for _, name := range interfaces {
			if iface.Name == name {
				inBrief = true
				break
			}
		}
		if !inBrief {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				result[iface.Name] = append(result[iface.Name], ipnet.IP.String())
			}
		}
	}
	return result
}