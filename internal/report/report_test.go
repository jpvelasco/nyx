package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/recommendations"
)

func TestRenderJSON(t *testing.T) {
	report := &models.AuditReport{
		Audit:  "test-site",
		Status: models.StatusPass,
		Summary: models.ReportSummary{
			Pass: 2,
			Fail: 0,
		},
		Findings: []models.CheckResult{
			{CheckType: "dummy", Status: models.StatusPass, Summary: "ok"},
		},
	}

	var buf bytes.Buffer
	if err := RenderJSON(&buf, report); err != nil {
		t.Fatalf("RenderJSON error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `"audit": "test-site"`) {
		t.Error("expected site in JSON output")
	}
	if !strings.Contains(out, "dummy") {
		t.Error("expected finding in JSON")
	}
}

func TestRenderResultJSON(t *testing.T) {
	res := &models.CheckResult{
		CheckType: "isolation",
		Status:    models.StatusFail,
		Summary:   "blocked as expected",
	}

	var buf bytes.Buffer
	if err := RenderResultJSON(&buf, res); err != nil {
		t.Fatalf("RenderResultJSON error: %v", err)
	}
	if !strings.Contains(buf.String(), "isolation") {
		t.Error("expected check type in result JSON")
	}
}

func TestRenderHuman(t *testing.T) {
	report := &models.AuditReport{
		Audit:  "home-lab",
		Status: models.StatusWarn,
		Summary: models.ReportSummary{
			Pass: 1, Fail: 0, Warn: 1, Error: 0, Skip: 0,
		},
		Runner: models.RunnerContext{
			LocalIPs: []string{"192.168.1.50"},
			Networks: []string{"trusted"},
		},
		Findings: []models.CheckResult{
			{CheckType: "subnet_discovery", Status: models.StatusWarn, Summary: "0 hosts"},
		},
	}

	var buf bytes.Buffer
	RenderHuman(&buf, report)
	out := buf.String()

	if !strings.Contains(out, "Site: home-lab") {
		t.Error("expected site header")
	}
	if !strings.Contains(out, "Status: WARN") {
		t.Error("expected status")
	}
	if !strings.Contains(out, "192.168.1.50") {
		t.Error("expected runner IP")
	}
	if !strings.Contains(out, "subnet_discovery") {
		t.Error("expected finding")
	}
	if !strings.Contains(out, "1 passed, 0 failed, 1 warnings") {
		t.Error("expected summary tally")
	}
}

func TestRenderRecommendations(t *testing.T) {
	recs := []recommendations.Recommendation{
		{
			Priority:    1,
			Category:    "isolation",
			Title:       "Fix IoT isolation",
			Description: "IoT can reach trusted",
			Remediation: "Add ACL",
		},
	}

	var buf bytes.Buffer
	RenderRecommendations(&buf, recs)
	out := buf.String()
	if !strings.Contains(out, "Fix IoT isolation") || !strings.Contains(out, "Add ACL") {
		t.Error("recommendations not rendered")
	}
}
