package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/credentials"
	"github.com/jpvelasco/nyx/internal/storepath"
)

func runCredentialsCmd(t *testing.T, args ...string) error {
	t.Helper()
	credentialsSetFlag = nil
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

	if err := runCredentialsCmd(t, "credentials", "set", "omada"); err == nil {
		t.Error("set without --set should fail")
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
