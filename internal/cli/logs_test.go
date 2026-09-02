package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeLogRotation creates a log rotation set under dir, with only the
// given generations present. Returns the live file path.
func writeLogRotation(t *testing.T, dir string, gens map[int]string) string {
	t.Helper()
	path := filepath.Join(dir, "nyx.log")
	for i, content := range gens {
		if i == 0 {
			if err := os.WriteFile(path, []byte(content), 0600); err != nil {
				t.Fatalf("writing live log: %v", err)
			}
			continue
		}
		if err := os.WriteFile(fmt.Sprintf("%s.%d", path, i), []byte(content), 0600); err != nil {
			t.Fatalf("writing log.%d: %v", i, err)
		}
	}
	return path
}

func setLogEnv(t *testing.T, path string) {
	t.Helper()
	t.Setenv("NYX_LOG_FILE", path)
}

// TestLogsExportEndToEnd exercises the command through cobra: reads the
// rotation set from NYX_LOG_FILE, filters, scrubs, and writes the artifact.
func TestLogsExportEndToEnd(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().Format("2006-01-02T15:04:05.000Z")
	live := `{"ts":"` + now + `","level":"info","msg":"audit","cmd":"nyx","version":"v0.4.0"}` + "\n" +
		`{"ts":"` + now + `","level":"warn","msg":"omada","cmd":"nyx","event":"retry","error":"controller refused"}` + "\n"
	setLogEnv(t, writeLogRotation(t, dir, map[int]string{0: live}))

	// Default file output (out flag empty): artifact lands in CWD with the
	// scrubbed JSON-lines + footer. Redirect CWD to a temp dir so the
	// default-name artifact is written in isolation — a leftover or
	// concurrent artifact must not be picked up, and a panic must not
	// pollute the package source dir.
	t.Chdir(t.TempDir())
	logsOut = ""
	if err := logsExportCmd.RunE(logsExportCmd, []string{}); err != nil {
		t.Fatalf("logs export: %v", err)
	}
	// Find the artifact in the working directory.
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading cwd: %v", err)
	}
	var artifact string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "nyx-logs-") && strings.HasSuffix(e.Name(), ".log") {
			artifact = e.Name()
		}
	}
	if artifact == "" {
		t.Fatalf("no nyx-logs-*.log artifact written to cwd")
	}
	defer os.Remove(artifact)
	b, err := os.ReadFile(artifact) // nosemgrep: go_filesystem_rule-fileread — artifact path built under t.TempDir()
	if err != nil {
		t.Fatalf("reading artifact %s: %v", artifact, err)
	}
	s := string(b)
	if !strings.Contains(s, `"msg":"audit"`) || !strings.Contains(s, `"msg":"omada"`) {
		t.Errorf("artifact missing entries:\n%s", s)
	}
	if !strings.Contains(s, "# lines=2 sources=1/4 scrub=scrubbed") {
		t.Errorf("footer missing/incorrect:\n%s", s)
	}

	// Stdout output + --last 1 + --level warn: only the warn omada line.
	logsOut = "-"
	logsLast = 1
	logsLevel = "warn"
	out, stderr := captureStreams(func() {
		if err := logsExportCmd.RunE(logsExportCmd, []string{}); err != nil {
			t.Fatalf("logs export stdout: %v", err)
		}
	})
	logsLast = 0
	logsLevel = "debug"
	if strings.Contains(out, `"msg":"audit"`) {
		t.Errorf("--last 1 --level warn kept an audit/info line:\n%s", out)
	}
	if !strings.Contains(out, `"msg":"omada"`) {
		t.Errorf("warn omada line missing from stdout:\n%s", out)
	}
	if !strings.Contains(out, "scrub=scrubbed") {
		t.Errorf("scrubbed footer missing:\n%s", out)
	}
	if strings.Contains(stderr, "no-scrub") {
		t.Errorf("scrubbed export must not print the raw warning, got %q", stderr)
	}
}

// TestLogsExportCmdFilter verifies --cmd matches the subsystem carried in
// msg (audit / omada), not just the constant cmd="nyx" field.
func TestLogsExportCmdFilter(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().Format("2006-01-02T15:04:05.000Z")
	live := `{"ts":"` + now + `","level":"info","msg":"audit","cmd":"nyx"}` + "\n" +
		`{"ts":"` + now + `","level":"warn","msg":"omada","cmd":"nyx","event":"retry"}` + "\n"
	setLogEnv(t, writeLogRotation(t, dir, map[int]string{0: live}))

	logsOut = "-"
	logsSubCmd = "omada"
	defer func() { logsSubCmd = "" }()
	out, _ := captureStreams(func() {
		if err := logsExportCmd.RunE(logsExportCmd, []string{}); err != nil {
			t.Fatalf("logs export --cmd omada: %v", err)
		}
	})
	if strings.Contains(out, `"msg":"audit"`) {
		t.Errorf("--cmd omada must drop audit lines:\n%s", out)
	}
	if !strings.Contains(out, `"msg":"omada"`) {
		t.Errorf("--cmd omada must keep omada lines:\n%s", out)
	}
}

// TestLogsExportNoScrub verifies the raw path: byte-identical lines and the
// stderr PII warning, plus the raw (UNSAFE) footer marker.
func TestLogsExportNoScrub(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().Format("2006-01-02T15:04:05.000Z")
	pii := `{"ts":"` + now + `","level":"info","msg":"audit","cmd":"nyx","target":"192.168.5.4"}`
	setLogEnv(t, writeLogRotation(t, dir, map[int]string{0: pii + "\n"}))

	logsOut = "-"
	logsNoScrub = true
	defer func() { logsNoScrub = false }()
	out, stderr := captureStreams(func() {
		if err := logsExportCmd.RunE(logsExportCmd, []string{}); err != nil {
			t.Fatalf("logs export --no-scrub: %v", err)
		}
	})
	if !strings.Contains(out, pii) {
		t.Errorf("raw export must be byte-identical:\n%s", out)
	}
	if !strings.Contains(stderr, "NOT scrubbed") {
		t.Errorf("raw export must warn on stderr, got %q", stderr)
	}
	if !strings.Contains(out, "scrub=raw (UNSAFE)") {
		t.Errorf("raw footer missing 'raw (UNSAFE)':\n%s", out)
	}
}

// TestLogsExportBadFlags: unparseable --since and --level are errors,
// never silent fallbacks.
func TestLogsExportBadFlags(t *testing.T) {
	dir := t.TempDir()
	setLogEnv(t, writeLogRotation(t, dir, map[int]string{0: "{}\n"}))
	logsOut = "-"

	logsSince = "yesterday"
	err := logsExportCmd.RunE(logsExportCmd, []string{})
	logsSince = ""
	if err == nil || !strings.Contains(err.Error(), "--since") {
		t.Errorf("bad --since must error, got %v", err)
	}

	logsLevel = "chatty"
	err = logsExportCmd.RunE(logsExportCmd, []string{})
	logsLevel = "debug"
	if err == nil || !strings.Contains(err.Error(), "--level") {
		t.Errorf("bad --level must error, got %v", err)
	}

	logsFormat = "yaml"
	err = logsExportCmd.RunE(logsExportCmd, []string{})
	logsFormat = "json"
	if err == nil || !strings.Contains(err.Error(), "--format") {
		t.Errorf("bad --format must error, got %v", err)
	}
}

// TestLogsExportOutFile verifies an explicit -o path writes the artifact
// there (not stdout) and confirms it on stdout.
func TestLogsExportOutFile(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().Format("2006-01-02T15:04:05.000Z")
	live := `{"ts":"` + now + `","level":"info","msg":"audit","cmd":"nyx"}` + "\n"
	setLogEnv(t, writeLogRotation(t, dir, map[int]string{0: live}))

	outPath := filepath.Join(dir, "artifact.log")
	logsOut = outPath
	out, _ := captureStreams(func() {
		if err := logsExportCmd.RunE(logsExportCmd, []string{}); err != nil {
			t.Fatalf("logs export -o: %v", err)
		}
	})
	logsOut = ""
	if !strings.Contains(out, "wrote log artifact to") {
		t.Errorf("file export must confirm the path on stdout, got %q", out)
	}
	if strings.Contains(out, `"msg":"audit"`) {
		t.Errorf("file export must not write lines to stdout, got %q", out)
	}
	b, err := os.ReadFile(outPath) // nosemgrep: go_filesystem_rule-fileread — artifact path built under t.TempDir()
	if err != nil {
		t.Fatalf("reading artifact %s: %v", outPath, err)
	}
	if !strings.Contains(string(b), `"msg":"audit"`) || !strings.Contains(string(b), "scrub=scrubbed") {
		t.Errorf("artifact missing entries or footer:\n%s", b)
	}
}

// TestLogsExportReadError: a log path that exists but cannot be scanned
// (a directory at the live-log path) surfaces the ReadRotation error,
// not a silent empty export.
func TestLogsExportReadError(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "nyx.log")
	if err := os.Mkdir(live, 0700); err != nil { // nosemgrep: go.lang.correctness.permissions.file_permission.incorrect-default-permission — dir needs execute to be a directory
		t.Fatalf("making directory at log path: %v", err)
	}
	setLogEnv(t, live)
	logsOut = "-"
	err := logsExportCmd.RunE(logsExportCmd, []string{})
	logsOut = ""
	if err == nil || !strings.Contains(err.Error(), "reading logs from") {
		t.Errorf("unscannable log must error, got %v", err)
	}
}

// TestLogsExportWriteError: an explicit -o path that cannot be created
// surfaces the WriteArtifact open error.
func TestLogsExportWriteError(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().Format("2006-01-02T15:04:05.000Z")
	live := `{"ts":"` + now + `","level":"info","msg":"audit","cmd":"nyx"}` + "\n"
	setLogEnv(t, writeLogRotation(t, dir, map[int]string{0: live}))

	logsOut = filepath.Join(dir, "no-such-dir", "artifact.log")
	out, _ := captureStreams(func() {
		err := logsExportCmd.RunE(logsExportCmd, []string{})
		if err == nil {
			t.Fatalf("bad -o path must error")
		}
		if !strings.Contains(err.Error(), "opening output file") {
			t.Errorf("expected an open-output error, got %v", err)
		}
	})
	logsOut = ""
	if strings.Contains(out, "wrote log artifact to") {
		t.Errorf("failed export must not confirm a write, got %q", out)
	}
}

// TestLogsExportRootHelp verifies the command is registered on the root:
// root help lists the "logs" group, and the export subcommand's own help
// advertises the scrub behavior.
func TestLogsExportRootHelp(t *testing.T) {
	out := captureStdout(func() {
		rootCmd.SetOut(nil)
		rootCmd.SetArgs([]string{"--help"})
		_ = rootCmd.Execute()
	})
	if !strings.Contains(out, "logs") {
		t.Errorf("root help missing 'logs' group:\n%s", out)
	}
	exportHelp := captureStdout(func() {
		_ = logsExportCmd.Help()
	})
	if !strings.Contains(exportHelp, "--no-scrub") || !strings.Contains(exportHelp, "--since") {
		t.Errorf("export --help missing flags:\n%s", exportHelp)
	}
}
