package cli

import (
	"context"
	"strings"
	"testing"

	providers "github.com/jpvelasco/nyx/internal/providers"
	"github.com/spf13/cobra"
)

func TestSplitCSV(t *testing.T) {
	if got := splitCSV(""); got != nil {
		t.Errorf("empty = %v, want nil", got)
	}
	if got := splitCSV("  "); got != nil {
		t.Errorf("blank = %v, want nil", got)
	}
	got := splitCSV(" a, b, ,c ")
	if strings.Join(got, "|") != "a|b|c" {
		t.Errorf("splitCSV = %v, want [a b c]", got)
	}
}

func TestParseProtocolList(t *testing.T) {
	got, err := parseProtocolList("")
	if err != nil || got != nil {
		t.Fatalf("empty = %v, %v", got, err)
	}
	got, err = parseProtocolList("6,17")
	if err != nil || len(got) != 2 || got[0] != 6 || got[1] != 17 {
		t.Fatalf("6,17 = %v, %v", got, err)
	}
	if _, err := parseProtocolList("tcp"); err == nil || !strings.Contains(err.Error(), "protocol numbers") {
		t.Fatalf("error = %v, want protocol-numbers message", err)
	}
}

func TestRequireNonEmpty(t *testing.T) {
	if err := requireNonEmpty("from", "trusted"); err != nil {
		t.Fatalf("present: %v", err)
	}
	if err := requireNonEmpty("from", ""); err == nil || !strings.Contains(err.Error(), "--from is required") {
		t.Fatalf("error = %v, want --from required", err)
	}
}

func TestAddDryRunFlag_DefaultTrue(t *testing.T) {
	var dryRun bool
	cmd := &cobra.Command{Use: "apply"}
	addDryRunFlag(cmd, &dryRun)
	if err := cmd.ParseFlags(nil); err != nil {
		t.Fatal(err)
	}
	if !dryRun {
		t.Fatal("dry-run default is false, want true")
	}
	if err := cmd.ParseFlags([]string{"--dry-run=false"}); err != nil {
		t.Fatal(err)
	}
	if dryRun {
		t.Fatal("--dry-run=false left the flag true")
	}
}

func TestPrintPlanAndApply_Text(t *testing.T) {
	saveRestoreGlobals(t)
	out := captureStdout(func() {
		if err := printPlan(struct{}{}, "create"); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "Plan: create") {
		t.Errorf("plan text = %q", out)
	}
	out = captureStdout(func() {
		if err := printApply(struct{}{}, "created", true); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "Dry-run: created") {
		t.Errorf("dry-run text = %q", out)
	}
	out = captureStdout(func() {
		if err := printApply(struct{}{}, "created", false); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, "Applied: created") {
		t.Errorf("apply text = %q", out)
	}
}

func TestPrintJSON(t *testing.T) {
	saveRestoreGlobals(t)
	jsonOutput = true
	out := captureStdout(func() {
		if err := printJSON(map[string]string{"outcome": "unchanged"}); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, `"outcome": "unchanged"`) {
		t.Errorf("JSON = %q", out)
	}
	out = captureStdout(func() {
		if err := printPlan(map[string]string{"action": "create"}, "create"); err != nil {
			t.Fatal(err)
		}
	})
	if !strings.Contains(out, `"action": "create"`) {
		t.Errorf("printPlan JSON = %q", out)
	}
}

func TestExtraTimeout_ZeroFallsBack(t *testing.T) {
	saveRestoreGlobals(t)
	timeout = "0s"
	dur, err := extraTimeout()
	if err != nil {
		t.Fatal(err)
	}
	if dur.Seconds() != 60 {
		t.Fatalf("zero timeout = %v, want 60s", dur)
	}
	timeout = "bogus"
	if _, err := extraTimeout(); err == nil || !strings.Contains(err.Error(), "invalid --timeout") {
		t.Fatalf("error = %v, want invalid-timeout", err)
	}
}

func TestWithProviderSession_MissingHost(t *testing.T) {
	saveRestoreOmadaExtGlobals(t)
	err := withProviderSession("omada", func(_ context.Context, _ providers.ImportOptions) error {
		t.Fatal("fn should not run without a host")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "controller host is required") {
		t.Fatalf("error = %v, want host-required", err)
	}
}
