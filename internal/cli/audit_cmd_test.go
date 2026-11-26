package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuditControllerTLSFlags(t *testing.T) {
	if f := auditCmd.Flags().Lookup("skip-tls-verify"); f == nil || f.Value.Type() != "bool" {
		t.Errorf("audit --skip-tls-verify flag missing or not bool")
	}
	if f := auditCmd.Flags().Lookup("ca-cert"); f == nil || f.Value.Type() != "string" {
		t.Errorf("audit --ca-cert flag missing or not string")
	}
}

func TestAuditMissingSpecError(t *testing.T) {
	// Set specFile to a path that definitely doesn't exist
	original := specFile
	specFile = "/tmp/nyx-test-nonexistent-spec-12345.yaml"
	defer func() { specFile = original }()

	err := auditCmd.RunE(auditCmd, []string{})
	if err == nil {
		t.Fatal("expected error for missing spec file, got nil")
	}

	msg := err.Error()
	if !strings.Contains(msg, "not found") {
		t.Errorf("error missing 'not found': %q", msg)
	}
	if !strings.Contains(msg, "nyx init --output") {
		t.Errorf("error missing 'nyx init --output' hint: %q", msg)
	}
	if !strings.Contains(msg, "nyx audit --spec") {
		t.Errorf("error missing 'nyx audit --spec' hint: %q", msg)
	}
}

func TestAuditRejectsInvalidProfileSelector(t *testing.T) {
	saveRestoreGlobals(t)

	specFile = filepath.Join(t.TempDir(), "spec.yaml")
	if err := os.WriteFile(specFile, []byte("version: 1\nsite: trusted\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ selector, errorText string }{{"missing=trusted", "unknown provider"}, {"omada=", "empty profile"}} {
		cmd := *auditCmd
		cmd.ResetFlags()
		cmd.Flags().StringToString("provider-profile", nil, "")
		if err := cmd.ParseFlags([]string{"--provider-profile", tc.selector}); err != nil {
			t.Fatal(err)
		}
		if err := cmd.RunE(&cmd, nil); err == nil || !strings.Contains(err.Error(), tc.errorText) {
			t.Errorf("unexpected selector result: %v", err)
		}
	}
}
