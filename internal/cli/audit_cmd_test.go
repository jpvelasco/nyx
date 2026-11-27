package cli

import (
	"encoding/json"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/pflag"
)

func TestAuditProviderProfilePowerShellExample(t *testing.T) {
	if _, err := exec.LookPath("pwsh"); err != nil {
		t.Skip("PowerShell is required to check npm launcher argument grouping")
	}
	// Read the example as data. The npm launcher forwards each parsed argument
	// as a string, so an unquoted array becomes one space-joined profile value.
	const parseExample = `
$tree = [System.Management.Automation.Language.Parser]::ParseInput([Console]::In.ReadToEnd(), [ref]$null, [ref]$null)
foreach ($statement in $tree.EndBlock.Statements) {
    $words = $statement.PipelineElements[0].CommandElements
    if ($words.Value -contains '--provider-profile') {
        ConvertTo-Json -Compress -InputObject @($words | ForEach-Object { [string]$_.SafeGetValue() })
    }
}`
	cmd := exec.Command("pwsh", "-NoProfile", "-NonInteractive", "-Command", parseExample)
	cmd.Stdin = strings.NewReader(auditCmd.Example)
	output, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	var args []string
	if err := json.Unmarshal(output, &args); err != nil {
		t.Fatalf("expected a multi-provider example with scalar arguments, got %q: %v", output, err)
	}
	flags := pflag.NewFlagSet("audit", pflag.ContinueOnError)
	flags.String("spec", "", "")
	profiles := flags.StringToString("provider-profile", nil, "")
	if err := flags.Parse(args); err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(*profiles, map[string]string{"omada": "trusted", "opnsense": "management"}) {
		t.Errorf("example selected profiles %v", *profiles)
	}
}

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
