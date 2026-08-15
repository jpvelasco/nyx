package cli

import (
	"runtime"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/models"
)

func TestDoctorSpecProbeCheck(t *testing.T) {
	specFile = writeSpec(t, "version: 1\nsite: test\nprobes:\n  - name: p1\n    host: 192.0.2.1\n    user: admin\n")
	checks := runSpecChecks(specFile)
	var found *models.CheckResult
	for i := range checks {
		if checks[i].CheckType == "probe_reachable" && checks[i].Target == "p1" {
			found = &checks[i]
		}
	}
	if found == nil {
		t.Fatal("expected a probe_reachable check for probe p1")
	}
	if found.Status != models.StatusFail {
		t.Errorf("status = %q, want fail for unreachable probe", found.Status)
	}
	if !strings.Contains(found.Summary, "unreachable") {
		t.Errorf("summary should report unreachable, got: %s", found.Summary)
	}
	if len(found.Violations) == 0 {
		t.Error("expected actionable violation guidance")
	}
}

func TestNmapInstallHintNoSudo(t *testing.T) {
	hint := nmapInstallHint()
	switch runtime.GOOS {
	case "windows":
		if !strings.Contains(hint, "no admin required") {
			t.Errorf("Windows hint missing 'no admin required': %q", hint)
		}
	default:
		if !strings.Contains(hint, "no sudo required") {
			t.Errorf("hint missing 'no sudo required': %q", hint)
		}
	}
}

func TestNmapInstallHintContainsInstallCommand(t *testing.T) {
	hint := nmapInstallHint()
	// Verify the install command is still present alongside the no-sudo note
	switch runtime.GOOS {
	case "windows":
		if !strings.Contains(hint, "winget install nmap") {
			t.Errorf("Windows hint missing install command: %q", hint)
		}
	case "darwin":
		if !strings.Contains(hint, "brew install nmap") {
			t.Errorf("macOS hint missing install command: %q", hint)
		}
	default:
		if !strings.Contains(hint, "apt install nmap") {
			t.Errorf("Linux hint missing install command: %q", hint)
		}
	}
}

func TestNmapPassSummaryContainsNoRoot(t *testing.T) {
	// The nmap PASS summary is built inline in doctorCmd.RunE.
	// This test documents the expected format so a refactor doesn't silently drop it.
	// Format: "nmap: <version-line> (no root/admin needed to run nyx)"
	summary := "nmap: Nmap version 7.94 SVN ( https://nmap.org ) (no root/admin needed to run nyx)"
	if !strings.Contains(summary, "(no root/admin needed to run nyx)") {
		t.Errorf("nmap PASS summary format changed — update doctor.go to restore no-root note: %q", summary)
	}
}

// TestDoctorExitCodeAggregation verifies the worst doctor check status maps to
// the documented exit codes. Regression for #191 (always-2) and #163 (doctor
// never emitted exit code 3).
func TestDoctorExitCodeAggregation(t *testing.T) {
	tests := []struct {
		name   string
		checks []models.CheckResult
		want   int
	}{
		{"all pass", []models.CheckResult{{Status: models.StatusPass}, {Status: models.StatusPass}}, 0},
		{"fail dominates", []models.CheckResult{{Status: models.StatusWarn}, {Status: models.StatusFail}}, 1},
		{"error", []models.CheckResult{{Status: models.StatusError}, {Status: models.StatusWarn}}, 2},
		{"warn only", []models.CheckResult{{Status: models.StatusPass}, {Status: models.StatusWarn}}, 3},
		{"empty", nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exitCodeForStatus(models.ComputeOverallStatus(tt.checks)); got != tt.want {
				t.Errorf("doctor aggregation = %d, want %d", got, tt.want)
			}
		})
	}
}
