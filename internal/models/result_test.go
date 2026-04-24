package models

import (
	"testing"
	"time"
)

func TestNewCheckResult(t *testing.T) {
	r := NewCheckResult("nmap", "subnet_discovery", "local", "10.0.20.0/24")
	if r.Tool != "nmap" {
		t.Errorf("expected tool 'nmap', got %q", r.Tool)
	}
	if r.Observed == nil {
		t.Error("expected Observed map to be initialized")
	}
	if r.Violations == nil {
		t.Error("expected Violations slice to be initialized")
	}
	if r.StartedAt.IsZero() {
		t.Error("expected StartedAt to be set")
	}
}

func TestCheckResultFinish(t *testing.T) {
	r := NewCheckResult("system", "route_check", "local", "10.0.10.1")
	time.Sleep(5 * time.Millisecond)
	r.Finish()
	if r.FinishedAt.IsZero() {
		t.Error("expected FinishedAt to be set")
	}
	if r.DurationMs <= 0 {
		t.Errorf("expected positive duration, got %d", r.DurationMs)
	}
}

func TestComputeOverallStatus(t *testing.T) {
	tests := []struct {
		name     string
		statuses []Status
		want     Status
	}{
		{"all pass", []Status{StatusPass, StatusPass}, StatusPass},
		{"one warn", []Status{StatusPass, StatusWarn}, StatusWarn},
		{"one fail", []Status{StatusPass, StatusFail, StatusWarn}, StatusFail},
		{"error wins", []Status{StatusPass, StatusFail, StatusError}, StatusError},
		{"empty", []Status{}, StatusPass},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var results []CheckResult
			for _, s := range tt.statuses {
				results = append(results, CheckResult{Status: s})
			}
			got := ComputeOverallStatus(results)
			if got != tt.want {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTally(t *testing.T) {
	results := []CheckResult{
		{Status: StatusPass},
		{Status: StatusPass},
		{Status: StatusFail},
		{Status: StatusWarn},
		{Status: StatusSkip},
	}
	s := Tally(results)
	if s.Pass != 2 {
		t.Errorf("pass: got %d want 2", s.Pass)
	}
	if s.Fail != 1 {
		t.Errorf("fail: got %d want 1", s.Fail)
	}
	if s.Warn != 1 {
		t.Errorf("warn: got %d want 1", s.Warn)
	}
	if s.Skip != 1 {
		t.Errorf("skip: got %d want 1", s.Skip)
	}
}
