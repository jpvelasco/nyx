package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/models"
)

func TestProbeChecks_EmitsPerProbe(t *testing.T) {
	path := filepath.Join(t.TempDir(), "spec.yaml")
	content := "version: 1\nsite: test\nprobes:\n" +
		"  - name: p1\n    host: 192.0.2.1\n    user: admin\n" +
		"  - name: p2\n    host: 192.0.2.2\n    user: admin\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	checks := ProbeChecks(path)
	if len(checks) != 2 {
		t.Fatalf("expected 2 probe checks, got %d", len(checks))
	}
	for _, c := range checks {
		if c.CheckType != "probe_reachable" {
			t.Errorf("check_type = %q, want probe_reachable", c.CheckType)
		}
		if c.Status != models.StatusFail {
			t.Errorf("status = %q, want fail for unreachable probe %s", c.Status, c.Target)
		}
		if !strings.Contains(c.Summary, "unreachable") {
			t.Errorf("summary should report unreachable, got: %s", c.Summary)
		}
	}
}

func TestProbeChecks_MissingFileReturnsNil(t *testing.T) {
	if checks := ProbeChecks(filepath.Join(t.TempDir(), "missing.yaml")); checks != nil {
		t.Fatalf("expected nil for unloadable spec, got %d checks", len(checks))
	}
}
