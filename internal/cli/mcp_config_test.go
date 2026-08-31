package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// runMcpConfigCmd executes `mcp config` with the given extra flags and
// returns its stdout.
func runMcpConfigCmd(t *testing.T, args ...string) string {
	t.Helper()
	// Reset the flag-bound vars: pflag only writes provided flags, so a
	// value set by a previous test would otherwise leak into this one.
	mcpConfigHarness, mcpConfigCommand, mcpConfigWrite = "claude", "", ""
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetArgs(append([]string{"mcp", "config"}, args...))
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("mcp config %v: %v", args, err)
	}
	return buf.String()
}

func TestMcpConfigClaudeSnippet(t *testing.T) {
	out := runMcpConfigCmd(t, "--harness", "claude", "--command", "nyx")

	var parsed struct {
		MCPServers map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"mcpServers"`
	}
	block := out[:strings.Index(out, "\n#")]
	if err := json.Unmarshal([]byte(block), &parsed); err != nil {
		t.Fatalf("snippet block is not valid JSON: %v\n%s", err, block)
	}
	entry, ok := parsed.MCPServers["nyx"]
	if !ok {
		t.Fatalf("snippet missing nyx entry: %q", out)
	}
	if entry.Command != "nyx" || len(entry.Args) != 2 || entry.Args[0] != "mcp" || entry.Args[1] != "serve" {
		t.Errorf("nyx entry = %+v, want command=nyx args=[mcp serve]", entry)
	}

	note := out[strings.Index(out, "\n#"):]
	for _, v := range []string{"OMADA_HOST", "OMADA_CLIENT_ID", "OMADA_CLIENT_SECRET", "OMADA_SITE",
		"OPNSENSE_HOST", "OPNSENSE_API_KEY", "OPNSENSE_API_SECRET"} {
		if !strings.Contains(note, v) {
			t.Errorf("credential note missing %s:\n%s", v, note)
		}
	}
	if strings.Contains(out, "OMADA_USERNAME") {
		t.Error("snippet references the pre-OpenAPI OMADA_USERNAME var")
	}
}

func TestMcpConfigCodexSnippet(t *testing.T) {
	out := runMcpConfigCmd(t, "--harness", "codex", "--command", "/usr/local/bin/nyx")

	if !strings.Contains(out, "[mcp_servers.nyx]") {
		t.Fatalf("missing [mcp_servers.nyx] table:\n%s", out)
	}
	if !strings.Contains(out, `command = "/usr/local/bin/nyx"`) || !strings.Contains(out, `args = ["mcp", "serve"]`) {
		t.Fatalf("snippet missing command/args lines:\n%s", out)
	}
	for _, v := range []string{"OMADA_HOST", "OPNSENSE_API_KEY", "OPNSENSE_API_SECRET"} {
		if !strings.Contains(out, v) {
			t.Errorf("credential note missing %s", v)
		}
	}
}

func TestMcpConfigUnknownHarness(t *testing.T) {
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetArgs([]string{"mcp", "config", "--harness", "aider"})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "unknown --harness") {
		t.Errorf("unknown harness should error, got: %v", err)
	}
}

func TestMcpConfigWriteFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "nested", ".mcp.json")
	out := runMcpConfigCmd(t, "--harness", "claude", "--command", "nyx", "--write", target)
	if !strings.Contains(out, "wrote "+target) {
		t.Fatalf("stdout = %q, want wrote confirmation", out)
	}
	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("reading written file: %v", err)
	}
	if !json.Valid(raw) {
		t.Fatalf("written JSON is invalid:\n%s", raw)
	}
	if !strings.Contains(string(raw), "\"mcpServers\"") {
		t.Errorf("written file missing mcpServers:\n%s", raw)
	}

	// codex --write keeps the file valid TOML by embedding the note as # comments
	tomlTarget := filepath.Join(dir, "config.toml")
	runMcpConfigCmd(t, "--harness", "codex", "--command", "nyx", "--write", tomlTarget)
	raw, err = os.ReadFile(tomlTarget)
	if err != nil {
		t.Fatalf("reading written toml: %v", err)
	}
	if !strings.Contains(string(raw), "[mcp_servers.nyx]") || !strings.Contains(string(raw), "OMADA_HOST") {
		t.Fatalf("written toml missing table or credential note:\n%s", raw)
	}
}

func TestMcpConfigDefaultsToExecutablePath(t *testing.T) {
	abs, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	out := runMcpConfigCmd(t, "--harness", "claude")
	// The path is embedded through %q, so on Windows backslashes are
	// escaped; compare against the quoted form.
	if !strings.Contains(out, strconv.Quote(abs)) {
		t.Fatalf("default snippet should embed the executable path %q:\n%s", abs, out)
	}
}
