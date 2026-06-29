package models

import (
	"testing"
)

// TestCheckResultShape tests CheckResult structure
func TestCheckResultShape(t *testing.T) {
	result := &CheckResult{
		CheckType:    "subnet_discovery",
		Target:       "personal",
		Status:       StatusPass,
		Summary:      "25 hosts discovered in 10.0.20.0/24",
		Observed:     map[string]interface{}{"total": 25},
		Expected:     map[string]interface{}{"total": 25},
		Violations:   []string{},
	}

	if result == nil {
		t.Fatal("expected non-nil CheckResult")
	}

	if result.CheckType != "subnet_discovery" {
		t.Errorf("expected check_type 'subnet_discovery', got %q", result.CheckType)
	}

	if result.Target != "personal" {
		t.Errorf("expected target 'personal', got %q", result.Target)
	}

	if result.Status != StatusPass {
		t.Errorf("expected status StatusPass, got %v", result.Status)
	}
}

// TestCheckResultWithAllFields tests CheckResult with all fields populated
func TestCheckResultWithAllFields(t *testing.T) {
	result := &CheckResult{
		CheckType:    "subnet_discovery",
		Target:       "personal",
		Status:       StatusFail,
		Summary:      "25 hosts discovered in 10.0.20.0/24",
		Observed:     map[string]interface{}{"total": 25},
		Expected:     map[string]interface{}{"total": 20},
		Violations:   []string{"found 25 hosts, expected max 20"},
	}

	if result == nil {
		t.Fatal("expected non-nil CheckResult")
	}

	if len(result.Violations) != 1 {
		t.Errorf("expected 1 violation, got %d", len(result.Violations))
	}
}

// TestRunnerContextShape tests RunnerContext structure
func TestRunnerContextShape(t *testing.T) {
	context := &RunnerContext{
		Networks: []string{"personal", "gaming"},
	}

	if context == nil {
		t.Fatal("expected non-nil RunnerContext")
	}

	if len(context.Networks) != 2 {
		t.Errorf("expected 2 networks, got %d", len(context.Networks))
	}
}

// TestRunnerContextWithEmptyNetworks tests RunnerContext with empty networks
func TestRunnerContextWithEmptyNetworks(t *testing.T) {
	context := &RunnerContext{
		Networks: []string{},
	}

	if context == nil {
		t.Fatal("expected non-nil RunnerContext")
	}

	if len(context.Networks) != 0 {
		t.Errorf("expected 0 networks, got %d", len(context.Networks))
	}
}
