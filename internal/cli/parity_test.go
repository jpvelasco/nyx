package cli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/jpvelasco/nyx/internal/mcp"
	"github.com/jpvelasco/nyx/internal/providers"

	// Blank imports trigger provider init() so the parity guard sees the
	// real providers in tests (same pattern as cli_test.go).
	_ "github.com/jpvelasco/nyx/internal/providers/omada"
	_ "github.com/jpvelasco/nyx/internal/providers/opnsense"
)

// mcpCapabilityTools maps each provider to the MCP tools that cover every
// capability it advertises via Capabilities(). The map is the code-level
// record of the deliberate CLI/MCP surface split (see the "CLI/MCP surface
// split" note in AGENTS.md, added with #61):
//
//   - The CLI is the bundled user surface: every advertised capability is
//     one `nyx <vendor> <capability>` subcommand (info/import/check/inventory).
//   - The MCP is the fine-grained agent surface: per-collection observation
//     tools plus the generic run_audit / load_spec audit tools, and the
//     mutation plan/apply pairs (omada_plan / omada_apply_acl,
//     opnsense_plan_nat / opnsense_apply_nat) that have no CLI command.
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
		"inventory": {"omada_inventory", "omada_list_gateway_dhcp_users"},
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
		"check":     {"run_audit", "load_spec"},
		"inventory": {"opnsense_inventory"},
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
func TestProviderCapabilitySurfaceParity(t *testing.T) {
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
