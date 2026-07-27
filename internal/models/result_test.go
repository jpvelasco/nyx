package models

import (
	"strings"
	"testing"
	"time"
)

// --- NewCheckResult ---

func TestNewCheckResult(t *testing.T) {
	r := NewCheckResult("nmap", "subnet_discovery", "local", "10.0.0.0/24")
	if r.Tool != "nmap" {
		t.Errorf("expected tool 'nmap', got %q", r.Tool)
	}
	if r.CheckType != "subnet_discovery" {
		t.Errorf("expected check_type 'subnet_discovery', got %q", r.CheckType)
	}
	if r.Runner != "local" {
		t.Errorf("expected runner 'local', got %q", r.Runner)
	}
	if r.Target != "10.0.0.0/24" {
		t.Errorf("expected target '10.0.0.0/24', got %q", r.Target)
	}
	if r.Observed == nil {
		t.Error("expected non-nil Observed map")
	}
	if r.Expected == nil {
		t.Error("expected non-nil Expected map")
	}
	if r.Violations == nil {
		t.Error("expected non-nil Violations slice")
	}
	if r.StartedAt.IsZero() {
		t.Error("expected non-zero StartedAt")
	}
}

// --- Finish ---

func TestFinish(t *testing.T) {
	r := NewCheckResult("tool", "type", "runner", "target")
	time.Sleep(50 * time.Millisecond)
	r.Finish()
	if r.FinishedAt.IsZero() {
		t.Error("expected non-zero FinishedAt")
	}
	if r.DurationMs < 0 {
		t.Errorf("expected non-negative duration, got %d", r.DurationMs)
	}
	if r.DurationMs < 45 {
		t.Errorf("duration too small: %d ms (expected ~50ms)", r.DurationMs)
	}
}

// --- ComputeOverallStatus ---

func TestComputeOverallStatus_AllPass(t *testing.T) {
	results := []CheckResult{{Status: StatusPass}, {Status: StatusPass}}
	status := ComputeOverallStatus(results)
	if status != StatusPass {
		t.Errorf("expected StatusPass, got %s", status)
	}
}

func TestComputeOverallStatus_MixedPassWarn(t *testing.T) {
	results := []CheckResult{{Status: StatusPass}, {Status: StatusWarn}}
	status := ComputeOverallStatus(results)
	if status != StatusWarn {
		t.Errorf("expected StatusWarn, got %s", status)
	}
}

func TestComputeOverallStatus_HasError(t *testing.T) {
	results := []CheckResult{{Status: StatusPass}, {Status: StatusError}}
	status := ComputeOverallStatus(results)
	if status != StatusError {
		t.Errorf("expected StatusError, got %s", status)
	}
}

func TestComputeOverallStatus_FailOverridesError(t *testing.T) {
	// Fail takes precedence over Error
	results := []CheckResult{{Status: StatusError}, {Status: StatusFail}}
	status := ComputeOverallStatus(results)
	if status != StatusFail {
		t.Errorf("expected StatusFail (overrides error), got %s", status)
	}
}

func TestComputeOverallStatus_SkipOnly(t *testing.T) {
	results := []CheckResult{{Status: StatusPass}, {Status: StatusSkip}}
	status := ComputeOverallStatus(results)
	if status != StatusPass {
		t.Errorf("expected StatusPass, got %s", status)
	}
}

func TestComputeOverallStatus_Empty(t *testing.T) {
	status := ComputeOverallStatus(nil)
	if status != StatusPass {
		t.Errorf("expected StatusPass for empty results, got %s", status)
	}
}

func TestComputeOverallStatus_MixedAll(t *testing.T) {
	results := []CheckResult{
		{Status: StatusPass},
		{Status: StatusWarn},
		{Status: StatusError},
		{Status: StatusFail},
		{Status: StatusSkip},
	}
	status := ComputeOverallStatus(results)
	if status != StatusFail {
		t.Errorf("expected StatusFail, got %s", status)
	}
}

// --- Tally ---

func TestTally(t *testing.T) {
	results := []CheckResult{
		{Status: StatusPass},
		{Status: StatusPass},
		{Status: StatusFail},
		{Status: StatusWarn},
		{Status: StatusError},
		{Status: StatusSkip},
	}
	s := Tally(results)
	if s.Pass != 2 {
		t.Errorf("expected 2 pass, got %d", s.Pass)
	}
	if s.Fail != 1 {
		t.Errorf("expected 1 fail, got %d", s.Fail)
	}
	if s.Warn != 1 {
		t.Errorf("expected 1 warn, got %d", s.Warn)
	}
	if s.Error != 1 {
		t.Errorf("expected 1 error, got %d", s.Error)
	}
	if s.Skip != 1 {
		t.Errorf("expected 1 skip, got %d", s.Skip)
	}
}

func TestTally_Empty(t *testing.T) {
	s := Tally(nil)
	if s.Pass != 0 || s.Fail != 0 || s.Warn != 0 || s.Error != 0 || s.Skip != 0 {
		t.Errorf("expected all zeros, got %+v", s)
	}
}

// --- AuditReport ---

func TestAuditReportStructure(t *testing.T) {
	report := &AuditReport{
		Audit:  "mysite",
		Status: StatusPass,
		Summary: ReportSummary{
			Pass: 3,
			Fail: 1,
		},
		Runner: RunnerContext{
			LocalIPs: []string{"192.168.1.5"},
			Networks: []string{"personal"},
		},
		Findings: []CheckResult{
			{CheckType: "subnet_discovery", Status: StatusPass},
		},
	}
	if report.Audit != "mysite" {
		t.Errorf("expected audit 'mysite', got %q", report.Audit)
	}
	if report.Summary.Pass != 3 {
		t.Errorf("expected 3 pass, got %d", report.Summary.Pass)
	}
	if len(report.Runner.LocalIPs) != 1 {
		t.Errorf("expected 1 local IP, got %d", len(report.Runner.LocalIPs))
	}
	if len(report.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(report.Findings))
	}
}

// --- Status constants ---

func TestStatusConstants(t *testing.T) {
	if StatusPass != "pass" {
		t.Errorf("expected 'pass', got %q", StatusPass)
	}
	if StatusFail != "fail" {
		t.Errorf("expected 'fail', got %q", StatusFail)
	}
	if StatusWarn != "warn" {
		t.Errorf("expected 'warn', got %q", StatusWarn)
	}
	if StatusError != "error" {
		t.Errorf("expected 'error', got %q", StatusError)
	}
	if StatusSkip != "skip" {
		t.Errorf("expected 'skip', got %q", StatusSkip)
	}
}

// --- Recommendation ---

func TestRecommendationStructure(t *testing.T) {
	rec := Recommendation{
		Priority:    1,
		Category:    "network",
		Title:       "Add missing network",
		Description: "The guest network is not defined in the spec.",
		Remediation: "Add a network entry for 192.168.2.0/24.",
		Affected:    []string{"subnet_discovery:guest"},
		SpecPatch:   "+ networks:\n+   - name: guest\n+     cidr: 192.168.2.0/24",
	}
	if rec.Priority != 1 {
		t.Errorf("expected priority 1, got %d", rec.Priority)
	}
	if len(rec.Affected) != 1 {
		t.Errorf("expected 1 affected, got %d", len(rec.Affected))
	}
	if !strings.Contains(rec.SpecPatch, "guest") {
		t.Error("expected SpecPatch to contain 'guest'")
	}
}
