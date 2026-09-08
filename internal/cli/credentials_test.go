package cli

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jpvelasco/nyx/internal/credentials"
	"github.com/jpvelasco/nyx/internal/probe"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/jpvelasco/nyx/internal/storepath"
)

func runCredentialsCmd(t *testing.T, args ...string) error {
	t.Helper()
	credentialsSetFlag = nil
	credentialsVerifyLive = false
	rootCmd.SetArgs(args)
	return rootCmd.Execute()
}

func TestCredentialsCmdRoundtrip(t *testing.T) {
	t.Setenv("NYX_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials.json"))

	if err := runCredentialsCmd(t, "credentials", "set", "omada",
		"--set", "host=192.168.1.1", "--set", "client_id=cid-1", "--set", "client_secret=hunter2"); err != nil {
		t.Fatalf("set failed: %v", err)
	}

	out := captureStdout(func() {
		_ = runCredentialsCmd(t, "credentials", "list")
	})
	if !strings.Contains(out, "omada") || !strings.Contains(out, "default") {
		t.Errorf("list output missing entry: %q", out)
	}
	if strings.Contains(out, "hunter2") {
		t.Errorf("list leaked a secret: %q", out)
	}

	if err := runCredentialsCmd(t, "credentials", "verify", "omada"); err != nil {
		t.Errorf("verify should pass: %v", err)
	}

	if err := runCredentialsCmd(t, "credentials", "remove", "omada"); err != nil {
		t.Fatalf("remove failed: %v", err)
	}
	if err := runCredentialsCmd(t, "credentials", "verify", "omada"); err == nil {
		t.Error("verify after remove should fail")
	}
}

func TestCredentialsVerifyMissingFields(t *testing.T) {
	t.Setenv("NYX_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials.json"))

	if err := runCredentialsCmd(t, "credentials", "set", "omada", "--set", "host=192.168.1.1"); err != nil {
		t.Fatalf("set failed: %v", err)
	}
	err := runCredentialsCmd(t, "credentials", "verify", "omada")
	if err == nil || !strings.Contains(err.Error(), "client_id") {
		t.Errorf("verify should report missing client_id, got: %v", err)
	}
}

func TestCredentialsSetRequiresKV(t *testing.T) {
	t.Setenv("NYX_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials.json"))

	err := runCredentialsCmd(t, "credentials", "set", "omada")
	if err == nil || !strings.Contains(err.Error(), "use --set key=value or run on a TTY") {
		t.Errorf("set without --set off TTY = %v, want TTY hint", err)
	}
	if err := runCredentialsCmd(t, "credentials", "set", "omada", "--set", "novalue"); err == nil {
		t.Error("set with malformed --set should fail")
	}
}

func TestCredentialsVerifyNamedEntry(t *testing.T) {
	t.Setenv("NYX_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials.json"))

	if err := runCredentialsCmd(t, "credentials", "set", "probe", "home",
		"--set", "host=10.0.0.5", "--set", "username=ubuntu", "--set", "key=~/.ssh/id_ed25519"); err != nil {
		t.Fatalf("set failed: %v", err)
	}
	if err := runCredentialsCmd(t, "credentials", "verify", "probe", "home"); err != nil {
		t.Errorf("verify named entry should pass: %v", err)
	}
	if err := runCredentialsCmd(t, "credentials", "verify", "probe", "missing"); err == nil {
		t.Error("verify missing entry should fail")
	}
}

func TestCredentialsListAndRemoveNamed(t *testing.T) {
	t.Setenv("NYX_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials.json"))

	if err := runCredentialsCmd(t, "credentials", "set", "probe", "home",
		"--set", "host=10.0.0.5", "--set", "username=ubuntu", "--set", "key=~/.ssh/id_ed25519"); err != nil {
		t.Fatalf("set failed: %v", err)
	}

	out := captureStdout(func() {
		_ = runCredentialsCmd(t, "credentials", "list", "probe")
	})
	if strings.TrimSpace(out) != "home" {
		t.Errorf("list probe = %q, want home", out)
	}

	if err := runCredentialsCmd(t, "credentials", "remove", "probe", "home"); err != nil {
		t.Fatalf("remove named failed: %v", err)
	}
	if err := runCredentialsCmd(t, "credentials", "remove", "probe", "home"); err == nil {
		t.Error("remove missing entry should fail")
	}
}

func TestCredentialsListEmpty(t *testing.T) {
	t.Setenv("NYX_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials.json"))

	out := captureStdout(func() {
		_ = runCredentialsCmd(t, "credentials", "list")
	})
	if !strings.Contains(out, "no credentials stored") {
		t.Errorf("list on empty store = %q", out)
	}
}

func TestCredentialsVerifyNoEntries(t *testing.T) {
	t.Setenv("NYX_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials.json"))

	if err := runCredentialsCmd(t, "credentials", "verify"); err == nil {
		t.Error("verify with no entries should fail")
	}
}

func TestCredentialsSetStoreError(t *testing.T) {
	tmpDir := t.TempDir()
	blocker := filepath.Join(tmpDir, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	t.Setenv("NYX_CREDENTIALS_FILE", filepath.Join(blocker, "credentials.json"))

	if err := runCredentialsCmd(t, "credentials", "set", "omada", "--set", "host=h"); err == nil {
		t.Error("set against an unwritable store should fail")
	}
	if err := runCredentialsCmd(t, "credentials", "list"); err == nil {
		t.Error("list against an unwritable store should fail")
	}
	if err := runCredentialsCmd(t, "credentials", "remove", "omada"); err == nil {
		t.Error("remove against an unwritable store should fail")
	}
	if err := runCredentialsCmd(t, "credentials", "verify", "omada"); err == nil {
		t.Error("verify against an unwritable store should fail")
	}
}

func TestCredentialsVerifyUnknownProvider(t *testing.T) {
	t.Setenv("NYX_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials.json"))

	if err := runCredentialsCmd(t, "credentials", "set", "custom-vendor", "default", "--set", "token=abc"); err != nil {
		t.Fatalf("set failed: %v", err)
	}
	if err := runCredentialsCmd(t, "credentials", "verify", "custom-vendor"); err != nil {
		t.Errorf("verify unknown provider (presence only) should pass: %v", err)
	}
}

// BDD S3.2 (docs/bdd/mcp-credentials.md): the store path honors the
// NYX_CREDENTIALS_FILE override, shared by the CLI and the MCP server.
func TestStoreFileDefault(t *testing.T) {
	t.Setenv("NYX_CREDENTIALS_FILE", "")
	if got := storepath.StoreFile(); got != credentials.DefaultPath() {
		t.Errorf("StoreFile() = %q, want default %q", got, credentials.DefaultPath())
	}
}

func TestStoreFileHonorsEnvOverride(t *testing.T) {
	path := filepath.Join(t.TempDir(), "custom.json")
	t.Setenv("NYX_CREDENTIALS_FILE", path)
	if got := storepath.StoreFile(); got != path {
		t.Errorf("StoreFile() = %q, want the NYX_CREDENTIALS_FILE override", got)
	}
}

func TestCredentialsSetPromptsOnTTY(t *testing.T) {
	t.Setenv("NYX_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials.json"))
	restorePromptSeams(t)
	isTerminal = func(int) bool { return true }
	promptQueue := []string{"10.0.11.20", "cid-1", "Default"}
	readLine = func(_ io.Reader) (string, error) {
		if len(promptQueue) == 0 {
			return "", io.EOF
		}
		s := promptQueue[0]
		promptQueue = promptQueue[1:]
		return s, nil
	}
	readPassword = func(int) ([]byte, error) { return []byte("s3cret"), nil }
	var prompts strings.Builder
	promptOut = &prompts

	out := captureStdout(func() {
		if err := runCredentialsCmd(t, "credentials", "set", "omada"); err != nil {
			t.Fatalf("interactive set: %v", err)
		}
	})
	if !strings.Contains(out, "stored omada/default") {
		t.Errorf("stdout = %q, want stored omada/default", out)
	}
	if strings.Contains(out, "s3cret") || strings.Contains(prompts.String(), "s3cret") {
		t.Errorf("secret leaked: stdout=%q prompts=%q", out, prompts.String())
	}

	store, err := credentials.Open(storepath.StoreFile())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	entry, ok := store.Get("omada", "default")
	if !ok {
		t.Fatal("expected stored entry")
	}
	if entry["host"] != "10.0.11.20" || entry["client_id"] != "cid-1" ||
		entry["client_secret"] != "s3cret" || entry["site"] != "Default" {
		t.Errorf("entry = %v", entry)
	}
}

func TestCredentialsSetPromptsMissingRequiredOnly(t *testing.T) {
	t.Setenv("NYX_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials.json"))
	restorePromptSeams(t)
	isTerminal = func(int) bool { return true }
	promptIn = strings.NewReader("cid-1\n")
	readPassword = func(int) ([]byte, error) { return []byte("s3cret"), nil }
	promptOut = io.Discard

	if err := runCredentialsCmd(t, "credentials", "set", "omada", "--set", "host=10.0.11.20"); err != nil {
		t.Fatalf("partial interactive set: %v", err)
	}
	store, err := credentials.Open(storepath.StoreFile())
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	entry, ok := store.Get("omada", "default")
	if !ok {
		t.Fatal("expected stored entry")
	}
	if entry["host"] != "10.0.11.20" || entry["client_id"] != "cid-1" || entry["client_secret"] != "s3cret" {
		t.Errorf("entry = %v", entry)
	}
	if _, hasSite := entry["site"]; hasSite {
		t.Errorf("partial --set must not prompt optional fields, got %v", entry)
	}
}

func TestCredentialsSetPromptErrors(t *testing.T) {
	t.Setenv("NYX_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials.json"))
	restorePromptSeams(t)
	isTerminal = func(int) bool { return true }
	promptOut = io.Discard

	readPassword = func(int) ([]byte, error) { return nil, errors.New("no tty") }
	promptIn = strings.NewReader("10.0.11.20\ncid-1\n")
	if err := runCredentialsCmd(t, "credentials", "set", "omada"); err == nil || !strings.Contains(err.Error(), "client_secret") {
		t.Errorf("password read error = %v", err)
	}

	readPassword = func(int) ([]byte, error) { return []byte("x"), nil }
	readLine = func(io.Reader) (string, error) { return "", errors.New("stdin closed") }
	if err := runCredentialsCmd(t, "credentials", "set", "omada"); err == nil || !strings.Contains(err.Error(), "host") {
		t.Errorf("line read error = %v", err)
	}
}

func TestCredentialsSetUnknownProviderEmptyTTY(t *testing.T) {
	t.Setenv("NYX_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials.json"))
	restorePromptSeams(t)
	isTerminal = func(int) bool { return true }
	promptIn = strings.NewReader("")
	promptOut = io.Discard

	if err := runCredentialsCmd(t, "credentials", "set", "custom"); err == nil || !strings.Contains(err.Error(), "at least one field is required") {
		t.Errorf("empty unknown-provider set = %v", err)
	}
}

func restorePromptSeams(t *testing.T) {
	t.Helper()
	origTerm, origPass, origLine := isTerminal, readPassword, readLine
	origIn, origOut := promptIn, promptOut
	t.Cleanup(func() {
		isTerminal, readPassword, readLine = origTerm, origPass, origLine
		promptIn, promptOut = origIn, origOut
	})
}

func TestCredentialsVerifyLiveSuccess(t *testing.T) {
	t.Setenv("NYX_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials.json"))
	restoreLiveSeams(t)
	var omada, opnsense, probes int
	liveOmada = func(_ context.Context, opts service.OmadaOptions) error {
		omada++
		if opts.Host != "10.0.11.20" || opts.ClientID != "cid" || opts.ClientSecret != "sec" {
			t.Errorf("omada opts = %+v", opts)
		}
		return nil
	}
	liveOpnsense = func(_ context.Context, opts service.OpnsenseOptions) error {
		opnsense++
		if opts.Host != "10.0.10.1" || opts.APIKey != "k" || opts.APISecret != "s" {
			t.Errorf("opnsense opts = %+v", opts)
		}
		return nil
	}
	liveProbe = func(_ context.Context, p probe.Probe) error {
		probes++
		if p.Host != "10.0.60.15" || p.User != "ubuntu" || p.Key != "~/.ssh/id_ed25519" {
			t.Errorf("probe = %+v", p)
		}
		return nil
	}

	if err := runCredentialsCmd(t, "credentials", "set", "omada",
		"--set", "host=10.0.11.20", "--set", "client_id=cid", "--set", "client_secret=sec"); err != nil {
		t.Fatalf("set omada: %v", err)
	}
	if err := runCredentialsCmd(t, "credentials", "set", "opnsense",
		"--set", "host=10.0.10.1", "--set", "api_key=k", "--set", "api_secret=s"); err != nil {
		t.Fatalf("set opnsense: %v", err)
	}
	if err := runCredentialsCmd(t, "credentials", "set", "probe", "home",
		"--set", "host=10.0.60.15", "--set", "username=ubuntu", "--set", "key=~/.ssh/id_ed25519"); err != nil {
		t.Fatalf("set probe: %v", err)
	}

	out := captureStdout(func() {
		if err := runCredentialsCmd(t, "credentials", "verify", "--live"); err != nil {
			t.Fatalf("verify --live: %v", err)
		}
	})
	if !strings.Contains(out, "ok (live)") {
		t.Errorf("stdout = %q, want ok (live)", out)
	}
	if omada != 1 || opnsense != 1 || probes != 1 {
		t.Errorf("live calls omada=%d opnsense=%d probe=%d", omada, opnsense, probes)
	}
}

func TestCredentialsVerifyLiveFailureSanitizesSecret(t *testing.T) {
	t.Setenv("NYX_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials.json"))
	restoreLiveSeams(t)
	liveOmada = func(context.Context, service.OmadaOptions) error {
		return errors.New("auth failed for secret-value")
	}

	if err := runCredentialsCmd(t, "credentials", "set", "omada",
		"--set", "host=10.0.11.20", "--set", "client_id=cid", "--set", "client_secret=secret-value"); err != nil {
		t.Fatalf("set: %v", err)
	}
	err := runCredentialsCmd(t, "credentials", "verify", "omada", "--live")
	if err == nil {
		t.Fatal("expected live verify failure")
	}
	if strings.Contains(err.Error(), "secret-value") {
		t.Errorf("live error leaked secret: %v", err)
	}
	if !strings.Contains(err.Error(), "[redacted]") {
		t.Errorf("live error = %v, want [redacted]", err)
	}
}

func TestCredentialsVerifyLiveSkipsUnknownProvider(t *testing.T) {
	t.Setenv("NYX_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials.json"))
	restoreLiveSeams(t)
	liveOmada = func(context.Context, service.OmadaOptions) error {
		t.Fatal("unknown provider must not call omada live")
		return nil
	}
	if err := runCredentialsCmd(t, "credentials", "set", "custom-vendor", "--set", "token=abc"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if err := runCredentialsCmd(t, "credentials", "verify", "custom-vendor", "--live"); err != nil {
		t.Errorf("unknown provider --live should skip: %v", err)
	}
}

func TestCredentialsVerifyLiveBadTimeout(t *testing.T) {
	t.Setenv("NYX_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials.json"))
	if err := runCredentialsCmd(t, "credentials", "set", "omada",
		"--set", "host=10.0.11.20", "--set", "client_id=cid", "--set", "client_secret=sec"); err != nil {
		t.Fatalf("set: %v", err)
	}
	orig := timeout
	t.Cleanup(func() { timeout = orig })
	timeout = "bogus"
	if err := runCredentialsCmd(t, "credentials", "verify", "omada", "--live"); err == nil || !strings.Contains(err.Error(), "invalid --timeout") {
		t.Errorf("bad timeout = %v", err)
	}
}

func restoreLiveSeams(t *testing.T) {
	t.Helper()
	origO, origP, origR := liveOmada, liveOpnsense, liveProbe
	t.Cleanup(func() {
		liveOmada, liveOpnsense, liveProbe = origO, origP, origR
	})
}

func TestLiveVerifyDefaultAndSanitizeNil(t *testing.T) {
	if err := liveVerify(context.Background(), "custom", credentials.Entry{"token": "x"}); err != nil {
		t.Fatalf("unknown provider liveVerify = %v", err)
	}
	if got := sanitizeLiveError(nil, credentials.Entry{"client_secret": "s"}); got != "" {
		t.Fatalf("nil sanitize = %q", got)
	}
}

func TestCredentialsVerifyLiveZeroTimeout(t *testing.T) {
	t.Setenv("NYX_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials.json"))
	restoreLiveSeams(t)
	var sawDeadline bool
	liveOmada = func(ctx context.Context, _ service.OmadaOptions) error {
		dl, ok := ctx.Deadline()
		sawDeadline = ok && time.Until(dl) > 20*time.Second
		return nil
	}
	if err := runCredentialsCmd(t, "credentials", "set", "omada",
		"--set", "host=10.0.11.20", "--set", "client_id=cid", "--set", "client_secret=sec"); err != nil {
		t.Fatalf("set: %v", err)
	}
	orig := timeout
	t.Cleanup(func() { timeout = orig })
	timeout = "0"
	if err := runCredentialsCmd(t, "credentials", "verify", "omada", "--live"); err != nil {
		t.Fatalf("verify --live timeout=0: %v", err)
	}
	if !sawDeadline {
		t.Fatal("expected a ~30s live deadline when --timeout is 0")
	}
}
