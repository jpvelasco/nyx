package cli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/jpvelasco/nyx/internal/mcp"
	"github.com/jpvelasco/nyx/internal/providers"
	omadaprov "github.com/jpvelasco/nyx/internal/providers/omada"
	opnsenseprov "github.com/jpvelasco/nyx/internal/providers/opnsense"
)

// mcpCapabilityTools maps each provider to the MCP tools that cover every
// capability it advertises via Capabilities(). The map is the code-level
// record of the deliberate CLI/MCP surface split (see the "CLI/MCP surface
// split" note in AGENTS.md, added with #61):
//
//   - The CLI is the bundled user surface: every advertised capability is
//     one `nyx <vendor> <capability>` subcommand (info/import/check/inventory).
//   - The MCP is the fine-grained agent surface: per-collection observation
//     tools plus the generic run_audit / load_spec audit tools. Mutation
//     plan/apply pairs are also on the CLI as extras (not Capabilities).
//
// `check` is covered by composition for both providers (import + run_audit);
// OPNsense `import` is covered by composition (the observation reads plus
// run_audit / load_spec) because the MCP has no dedicated OPNsense import
// tool. If a provider gains a new capability, add its mapping here — CI
// fails without one.
var mcpCapabilityTools = map[string]map[string][]string{
	"omada": {
		"info":      {"omada_get_info"},
		"import":    {"omada_import"},
		"check":     {"run_audit", "load_spec"},
		"inventory": {"omada_inventory", "omada_list_gateway_dhcp_users", "omada_get_client_topology", "omada_dhcp_path", "omada_get_dhcp_server_info", "omada_get_dhcp_snoop_status", "omada_list_dhcp_snoops", "omada_list_lan_multicasts", "omada_list_ssids"},
	},
	"opnsense": {
		"info": {"opnsense_get_info"},
		"import": {
			"opnsense_list_interfaces",
			"opnsense_list_firewall_rules",
			"opnsense_list_clients",
			"opnsense_list_services",
			"opnsense_list_gateways",
			"run_audit",
			"load_spec",
		},
		"check": {"run_audit", "load_spec"},
		"inventory": {
			"opnsense_inventory",
			"opnsense_list_bridges",
			"opnsense_list_interface_settings",
			"opnsense_get_dnsmasq_settings",
			"opnsense_get_unbound_settings",
			"opnsense_list_unbound_overrides",
			"opnsense_get_unbound_status",
			"opnsense_get_pf_statistics",
			"opnsense_list_kernel_routes",
			"opnsense_list_kea_subnets",
			"opnsense_list_kea_reservations",
			"opnsense_list_wireguard_servers",
			"opnsense_list_wireguard_clients",
			"opnsense_get_wireguard_status",
			"opnsense_list_vlans",
		},
	},
}

// TestProviderCapabilitySurfaceParity is the parity guard from #61: every
// capability a provider advertises via Capabilities() must be reachable on
// BOTH surfaces — at least one CLI subcommand (built by
// BuildProviderSubcommands) and at least one MCP tool (registered in the
// mcp tool table). A capability added to only one surface fails CI here.
//
// The MCP side is checked without any network I/O: credential environment
// and the encrypted store are neutralized, so a registered tool answers
// with its early credential/argument validation error instead of
// `unknown tool`.
func ensureProviderRegistered(t *testing.T, name string, p providers.Provider) {
	t.Helper()
	if providers.Get(name) != nil {
		return
	}
	if err := providers.Register(p); err != nil {
		t.Fatalf("re-register %s: %v", name, err)
	}
}

func TestProviderCapabilitySurfaceParity(t *testing.T) {
	ensureProviderRegistered(t, "omada", &omadaprov.OmadaProvider{})
	ensureProviderRegistered(t, "opnsense", &opnsenseprov.Provider{})
	// Neutralize every credential source so dispatched tools fail at
	// argument validation (host missing) before any controller contact.
	for _, env := range []string{
		"OMADA_HOST", "OMADA_CLIENT_ID", "OMADA_CLIENT_SECRET", "OMADA_SITE",
		"OPNSENSE_HOST", "OPNSENSE_API_KEY", "OPNSENSE_API_SECRET",
	} {
		t.Setenv(env, "")
	}
	// A non-existent store file makes credentials.Overlay a no-op.
	t.Setenv("NYX_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "none.json"))

	server := mcp.NewServer()
	toolRegistered := func(name string) bool {
		text, _ := server.DispatchToolForTest(context.Background(), name, map[string]interface{}{})
		return !strings.Contains(text, "unknown tool")
	}

	for _, p := range providers.List() {
		for _, cap := range p.Capabilities() {
			t.Run(p.Name()+"/"+cap, func(t *testing.T) {
				// MCP side: the capability must have a mapping, and every
				// mapped tool must actually be registered.
				tools, ok := mcpCapabilityTools[p.Name()][cap]
				if !ok || len(tools) == 0 {
					t.Fatalf("capability %q of provider %q has no MCP tool mapping — add it to mcpCapabilityTools (map to the generic run_audit/load_spec tools when the capability is covered by composition)", cap, p.Name())
				}
				for _, tool := range tools {
					if !toolRegistered(tool) {
						t.Errorf("MCP tool %q is mapped for provider %q capability %q but is not registered — the tool table and the parity map have drifted", tool, p.Name(), cap)
					}
				}

				// CLI side: the capability must be a subcommand of the
				// vendor command built from Capabilities().
				fresh := &cobra.Command{Use: "nyx"}
				BuildProviderSubcommands(fresh)
				var vendor *cobra.Command
				for _, c := range fresh.Commands() {
					if c.Name() == p.Name() {
						vendor = c
					}
				}
				if vendor == nil {
					t.Fatalf("no %q vendor command after BuildProviderSubcommands", p.Name())
				}
				found := false
				for _, c := range vendor.Commands() {
					if c.Name() == cap {
						found = true
					}
				}
				if !found {
					t.Errorf("capability %q of provider %q has no %q CLI subcommand — wire it in BuildProviderSubcommands or stop advertising it in Capabilities()", cap, p.Name(), cap)
				}
			})
		}
	}
}

// mcpMutationCLI maps every Omada/OPNsense MCP mutation tool to the CLI
// extra subcommand that wraps the same service method. A documented
// equivalent can live here when the names cannot match 1:1 (underscores
// become hyphens; omada_plan stays `plan` to match the existing extra
// style). Reads that already have extras are listed so a new mutation
// cannot ship MCP-only without failing this test.
var mcpMutationCLI = map[string]string{
	"omada_plan":                      "plan",
	"omada_apply_acl":                 "apply-acl",
	"omada_plan_port":                 "plan-port",
	"omada_apply_port_profile":        "apply-port-profile",
	"omada_plan_lan":                  "plan-lan",
	"omada_apply_lan":                 "apply-lan",
	"omada_plan_ssid":                 "plan-ssid",
	"omada_apply_ssid":                "apply-ssid",
	"opnsense_plan_nat":               "plan-nat",
	"opnsense_apply_nat":              "apply-nat",
	"opnsense_plan_vlan":              "plan-vlan",
	"opnsense_apply_vlan":             "apply-vlan",
	"opnsense_plan_filter":            "plan-filter",
	"opnsense_apply_filter":           "apply-filter",
	"opnsense_plan_unbound_override":  "plan-unbound-override",
	"opnsense_apply_unbound_override": "apply-unbound-override",
	"opnsense_plan_dhcp":              "plan-dhcp",
	"opnsense_apply_dhcp":             "apply-dhcp",
}

func vendorOfTool(name string) string {
	switch {
	case strings.HasPrefix(name, "omada_"):
		return "omada"
	case strings.HasPrefix(name, "opnsense_"):
		return "opnsense"
	default:
		return ""
	}
}

func isMutationTool(name string) bool {
	rest := name
	if i := strings.Index(name, "_"); i >= 0 {
		rest = name[i+1:]
	}
	return strings.HasPrefix(rest, "plan") || strings.HasPrefix(rest, "apply")
}

// TestNamedToolCLIParity is the #95 guard: every MCP omada_* / opnsense_*
// mutation tool must have a CLI extra subcommand (or a documented
// equivalent in mcpMutationCLI). Capability parity stays in
// TestProviderCapabilitySurfaceParity; extras stay off Capabilities().
func TestNamedToolCLIParity(t *testing.T) {
	// coverage_test.go Reset()s the registry after fake-provider tests.
	ensureProviderRegistered(t, "omada", &omadaprov.OmadaProvider{})
	ensureProviderRegistered(t, "opnsense", &opnsenseprov.Provider{})
	fresh := &cobra.Command{Use: "nyx"}
	BuildProviderSubcommands(fresh)
	vendorCmds := map[string]*cobra.Command{}
	for _, c := range fresh.Commands() {
		vendorCmds[c.Name()] = c
		vendorCmds[c.Use] = c
	}

	for _, tool := range mcp.ToolNames() {
		vendor := vendorOfTool(tool)
		if vendor == "" || !isMutationTool(tool) {
			continue
		}
		t.Run(tool, func(t *testing.T) {
			cliName, ok := mcpMutationCLI[tool]
			if !ok || cliName == "" {
				t.Fatalf("MCP mutation tool %q has no CLI mapping — add it to mcpMutationCLI (or implement the extra subcommand)", tool)
			}
			vendorCmd := vendorCmds[vendor]
			if vendorCmd == nil {
				t.Fatalf("no %q vendor command after BuildProviderSubcommands", vendor)
			}
			found := false
			for _, c := range vendorCmd.Commands() {
				if c.Name() == cliName {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("MCP tool %q maps to CLI %q %s, but that extra is not registered", tool, vendor, cliName)
			}
		})
	}
}
