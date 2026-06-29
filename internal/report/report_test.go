package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/models"
)

// TestRenderJSON tests JSON rendering of an audit report
func TestRenderJSON(t *testing.T) {
	var buf bytes.Buffer
	report := &models.AuditReport{
		Audit:   "test",
		Status:  models.StatusPass,
		Summary: models.ReportSummary{},
		Runner:  models.RunnerContext{},
		Findings: []models.CheckResult{
			{
				CheckType:    "subnet_discovery",
				Target:       "personal",
				Status:       models.StatusPass,
				Summary:      "25 hosts discovered in 10.0.20.0/24",
				Observed:     map[string]interface{}{"total": 25},
				Expected:     map[string]interface{}{"total": 25},
				Violations:   []string{},
			},
		},
	}

	err := RenderJSON(&buf, report)
	if err != nil {
		t.Fatalf("RenderJSON error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "audit") {
		t.Error("expected output to contain 'audit'")
	}
}

// TestRenderWithFailures tests JSON rendering with failures
func TestRenderWithFailures(t *testing.T) {
	var buf bytes.Buffer
	report := &models.AuditReport{
		Audit:   "test",
		Status:  models.StatusFail,
		Summary: models.ReportSummary{},
		Runner:  models.RunnerContext{},
		Findings: []models.CheckResult{
			{
				CheckType:    "subnet_discovery",
				Target:       "personal",
				Status:       models.StatusFail,
				Summary:      "0 hosts discovered in 10.0.20.0/24",
				Observed:     map[string]interface{}{"total": 0},
				Expected:     map[string]interface{}{"total": 25},
				Violations:   []string{"expected 25 hosts but found 0"},
			},
		},
	}

	err := RenderJSON(&buf, report)
	if err != nil {
		t.Fatalf("RenderJSON error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, "status") || !strings.Contains(output, "fail") {
		t.Error("expected output to indicate failure status")
	}
}
