package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jpvelasco/nyx/internal/mcp"
	"github.com/spf13/cobra"
)

var (
	mcpConfigHarness string
	mcpConfigCommand string
	mcpConfigWrite   string
)

var mcpConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Print a ready-to-paste MCP harness config snippet",
	Long: `Print a ready-to-paste configuration block that registers the nyx MCP
server with an agent harness (claude: mcpServers JSON, codex: mcp_servers
TOML). Use --write to write the snippet to a file instead.

Credentials are never part of the snippet. The server reads them from
environment variables (see the note under the snippet) or the encrypted
store (nyx credentials set) — not from the config file. Export the env
vars in the harness environment, or seed the store once.`,
	Example: `  nyx mcp config --harness claude
  nyx mcp config --harness codex --command ~/.local/bin/nyx
  nyx mcp config --harness claude --write .mcp.json`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		command := mcpConfigCommand
		if command == "" {
			abs, err := os.Executable()
			if err != nil {
				return fmt.Errorf("resolving the nyx executable path: %w (pass an explicit --command)", err)
			}
			command = abs
		}

		block, ok := configBlock(mcpConfigHarness, command)
		if !ok {
			return fmt.Errorf("unknown --harness %q (use claude or codex)", mcpConfigHarness)
		}

		if mcpConfigWrite != "" {
			//nolint:gosec
			if err := os.MkdirAll(filepath.Dir(mcpConfigWrite), 0o700); err != nil { // nosemgrep
				return fmt.Errorf("creating directory for --write: %w", err)
			}
			content := block
			// TOML comments are valid in the file itself; the JSON file
			// must stay strict, so the credential note goes to stdout.
			if mcpConfigHarness == "codex" {
				content += "\n" + credentialNote()
			}
			if err := os.WriteFile(mcpConfigWrite, []byte(content), 0o600); err != nil {
				return fmt.Errorf("writing --write target: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "wrote "+mcpConfigWrite)
			if mcpConfigHarness == "claude" {
				fmt.Fprintln(cmd.OutOrStdout(), credentialNote())
			}
			return nil
		}

		fmt.Fprint(cmd.OutOrStdout(), block)
		fmt.Fprintln(cmd.OutOrStdout(), credentialNote())
		return nil
	},
}

// configBlock renders the harness config block for harness, or ok=false
// for an unknown harness. The claude block is strict JSON; the codex
// block is TOML (valid on its own).
func configBlock(harness, command string) (string, bool) {
	switch harness {
	case "claude":
		return fmt.Sprintf(`{
  "mcpServers": {
    "nyx": {
      "command": %q,
      "args": ["mcp", "serve"]
    }
  }
}
`, command), true
	case "codex":
		return fmt.Sprintf(`[mcp_servers.nyx]
command = %q
args = ["mcp", "serve"]
`, command), true
	default:
		return "", false
	}
}

// credentialNote documents the credential env vars (names only — never
// values) and points at the encrypted store. It is appended under the
// snippet in both harness outputs.
func credentialNote() string {
	vars := append(append([]string{}, mcp.OmadaCredEnvVars...), mcp.OpnsenseCredEnvVars...)
	var sb strings.Builder
	sb.WriteString("# Credentials: export these in the harness environment, or seed the\n")
	sb.WriteString("# encrypted store once (`nyx credentials set`) — never put values in the config:\n")
	for _, v := range vars {
		fmt.Fprintf(&sb, "#   %s\n", v)
	}
	return sb.String()
}

func init() {
	mcpConfigCmd.Flags().StringVar(&mcpConfigHarness, "harness", "claude", "Harness format: claude (mcpServers JSON) or codex (mcp_servers TOML)")
	mcpConfigCmd.Flags().StringVar(&mcpConfigCommand, "command", "", "Path to the nyx binary in the snippet (default: current executable path)")
	mcpConfigCmd.Flags().StringVar(&mcpConfigWrite, "write", "", "Write the snippet to this file instead of stdout")
	mcpCmd.AddCommand(mcpConfigCmd)
}
