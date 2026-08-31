package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// runMcpConfigCmd executes `mcp config` with the given extra flags and
// returns its stdout; it fails the test if the command errors.
func runMcpConfigCmd(t *testing.T, args ...string) string {
	t.Helper()
	out, err := runMcpConfigCmdRaw(t, args...)
	if err != nil {
		t.Fatalf("mcp config %v: %v", args, err)
	}
	return out
}

// runMcpConfigCmdRaw executes `mcp config` and returns stdout plus the
// error; error-path tests assert on the error instead of failing.
func runMcpConfigCmdRaw(t *testing.T, args ...string) (string, error) {
	t.Helper()
	// Reset the flag-bound vars: pflag only writes provided flags, so a
	// value set by a previous test would otherwise leak into this one.
	mcpConfigHarness, mcpConfigCommand, mcpConfigWrite = "claude", "", ""
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetArgs(append([]string{"mcp", "config"}, args...))
	err := rootCmd.Execute()
	return buf.String(), err
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
	// Codacy false positive: target is created under t.TempDir(), not from user input.
	raw, err := os.ReadFile(target) // nosemgrep: go_filesystem_rule-fileread
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
	raw, err = os.ReadFile(tomlTarget) // nosemgrep: go_filesystem_rule-fileread
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

func TestMcpConfigWriteErrors(t *testing.T) {
	t.Run("unresolvable executable without --command", func(t *testing.T) {
		old := resolveExecutable
		resolveExecutable = func() (string, error) {
			return "", errors.New("no executable")
		}
		t.Cleanup(func() { resolveExecutable = old })

		_, err := runMcpConfigCmdRaw(t, "--harness", "claude")
		if err == nil || !strings.Contains(err.Error(), "pass an explicit --command") {
			t.Fatalf("expected actionable executable error, got: %v", err)
		}
	})

	t.Run("write target is a directory", func(t *testing.T) {
		// t.TempDir() is itself a directory: MkdirAll on its parent
		// succeeds, WriteFile fails.
		dir := t.TempDir()
		_, err := runMcpConfigCmdRaw(t, "--harness", "claude", "--command", "nyx", "--write", dir)
		if err == nil || !strings.Contains(err.Error(), "writing --write target") {
			t.Fatalf("expected write error, got: %v", err)
		}
	})

	t.Run("write target parent is a file", func(t *testing.T) {
		dir := t.TempDir()
		// The target's parent exists as a regular file, so MkdirAll fails.
		parent := filepath.Join(dir, "notadir")
		if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
			t.Fatalf("creating parent file: %v", err)
		}
		target := filepath.Join(parent, ".mcp.json")
		_, err := runMcpConfigCmdRaw(t, "--harness", "claude", "--command", "nyx", "--write", target)
		if err == nil || !strings.Contains(err.Error(), "creating directory") {
			t.Fatalf("expected directory-creation error, got: %v", err)
		}
	})
}
