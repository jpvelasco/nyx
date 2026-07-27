package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/recommendations"
)

// =====================================================================
// RenderJSON
// =====================================================================

func TestRenderJSON_AllPass(t *testing.T) {
	var buf bytes.Buffer
	report := &models.AuditReport{
		Audit: "homelab", Status: models.StatusPass,
		Summary: models.ReportSummary{Pass: 3, Fail: 0, Warn: 0, Error: 0, Skip: 0},
		Runner:  models.RunnerContext{LocalIPs: []string{"192.168.1.5"}, Networks: []string{"lan"}},
		Findings: []models.CheckResult{
			{CheckType: "subnet_discovery", Target: "lan", Status: models.StatusPass, Summary: "5 hosts found"},
			{CheckType: "dns_check", Target: "ns1", Status: models.StatusPass, Summary: "resolved ok"},
			{CheckType: "port_check", Target: "gw", Status: models.StatusPass, Summary: "ports open"},
		},
	}
	err := RenderJSON(&buf, report)
	if err != nil {
		t.Fatalf("RenderJSON error: %v", err)
	}

	var decoded models.AuditReport
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if decoded.Audit != "homelab" {
		t.Errorf("expected audit 'homelab', got %q", decoded.Audit)
	}
	if decoded.Status != models.StatusPass {
		t.Errorf("expected status pass, got %s", decoded.Status)
	}
	if decoded.Summary.Pass != 3 {
		t.Errorf("expected 3 pass, got %d", decoded.Summary.Pass)
	}
	if len(decoded.Findings) != 3 {
		t.Errorf("expected 3 findings, got %d", len(decoded.Findings))
	}
	// Verify indentation (two-space indent)
	if !strings.Contains(buf.String(), "  ") {
		t.Error("expected indented JSON output")
	}
}

func TestRenderJSON_WithFailures(t *testing.T) {
	var buf bytes.Buffer
	report := &models.AuditReport{
		Audit: "prod", Status: models.StatusFail,
		Summary: models.ReportSummary{Pass: 1, Fail: 2},
		Findings: []models.CheckResult{
			{CheckType: "subnet_discovery", Target: "dmz", Status: models.StatusFail,
				Summary: "0 hosts", Violations: []string{"expected 5 hosts but found 0"},
				Observed: map[string]interface{}{"total": 0},
				Expected: map[string]interface{}{"total": 5}},
			{CheckType: "isolation", Target: "guest->lan", Status: models.StatusFail,
				Summary: "isolation violation"},
		},
	}
	err := RenderJSON(&buf, report)
	if err != nil {
		t.Fatalf("RenderJSON error: %v", err)
	}

	output := buf.String()
	if !strings.Contains(output, `"status": "fail"`) {
		t.Error("expected status fail in JSON")
	}
	if !strings.Contains(output, "expected 5 hosts but found 0") {
		t.Error("expected violation text in JSON")
	}
}

func TestRenderJSON_WithEvidence(t *testing.T) {
	var buf bytes.Buffer
	report := &models.AuditReport{
		Audit: "lab", Status: models.StatusPass,
		Findings: []models.CheckResult{
			{CheckType: "route_check", Target: "8.8.8.8", Status: models.StatusPass,
				Evidence: []string{"via 192.168.1.1 dev eth0", "mtu 1500"}},
		},
	}
	err := RenderJSON(&buf, report)
	if err != nil {
		t.Fatalf("RenderJSON error: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &result); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	findings, _ := result["findings"].([]interface{})
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding")
	}
	f := findings[0].(map[string]interface{})
	evidence, _ := f["evidence"].([]interface{})
	if len(evidence) != 2 {
		t.Errorf("expected 2 evidence items, got %d", len(evidence))
	}
}

func TestRenderJSON_EmptyReport(t *testing.T) {
	var buf bytes.Buffer
	report := &models.AuditReport{Audit: "empty", Status: models.StatusPass}
	err := RenderJSON(&buf, report)
	if err != nil {
		t.Fatalf("RenderJSON error with empty report: %v", err)
	}

	var decoded models.AuditReport
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(decoded.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(decoded.Findings))
	}
}

func TestRenderJSON_AllStatuses(t *testing.T) {
	var buf bytes.Buffer
	report := &models.AuditReport{
		Audit: "mixed", Status: models.StatusWarn,
		Summary: models.ReportSummary{Pass: 1, Fail: 1, Warn: 1, Error: 1, Skip: 1},
		Findings: []models.CheckResult{
			{CheckType: "subnet_discovery", Status: models.StatusPass},
			{CheckType: "isolation", Status: models.StatusFail},
			{CheckType: "dns_check", Status: models.StatusWarn},
			{CheckType: "port_check", Status: models.StatusError},
			{CheckType: "route_check", Status: models.StatusSkip},
		},
	}
	err := RenderJSON(&buf, report)
	if err != nil {
		t.Fatalf("RenderJSON error: %v", err)
	}

	var decoded models.AuditReport
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(decoded.Findings) != 5 {
		t.Errorf("expected 5 findings, got %d", len(decoded.Findings))
	}
	if decoded.Summary.Skip != 1 {
		t.Errorf("expected 1 skip in summary, got %d", decoded.Summary.Skip)
	}
}

func TestRenderJSON_WithRecommendations(t *testing.T) {
	var buf bytes.Buffer
	report := &models.AuditReport{
		Audit: "lab", Status: models.StatusWarn,
		Findings: []models.CheckResult{{CheckType: "subnet_discovery", Status: models.StatusWarn}},
		Recommendations: []models.Recommendation{
			{Priority: 1, Category: "vantage_point", Title: "Wrong vantage point",
				Description: "runner is outside", Remediation: "add a probe"},
		},
	}
	err := RenderJSON(&buf, report)
	if err != nil {
		t.Fatalf("RenderJSON error: %v", err)
	}

	var decoded models.AuditReport
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(decoded.Recommendations) != 1 {
		t.Errorf("expected 1 recommendation, got %d", len(decoded.Recommendations))
	}
}

// =====================================================================
// RenderHuman
// =====================================================================

func TestRenderHuman_BasicReport(t *testing.T) {
	var buf bytes.Buffer
	report := &models.AuditReport{
		Audit: "homelab", Status: models.StatusPass,
		Summary: models.ReportSummary{Pass: 2, Fail: 0, Warn: 0, Error: 0, Skip: 0},
		Findings: []models.CheckResult{
			{CheckType: "subnet_discovery", Status: models.StatusPass, Summary: "5 hosts in 10.0.0.0/24"},
			{CheckType: "dns_check", Status: models.StatusPass, Summary: "resolver ok"},
		},
	}
	RenderHuman(&buf, report)

	output := buf.String()
	if !strings.Contains(output, "Site: homelab") {
		t.Error("expected site name")
	}
	if !strings.Contains(output, "Status: PASS") {
		t.Error("expected PASS status label")
	}
	if !strings.Contains(output, "[PASS] subnet_discovery: 5 hosts in 10.0.0.0/24") {
		t.Errorf("expected finding line, got:\n%s", output)
	}
	if !strings.Contains(output, "Summary: 2 passed, 0 failed, 0 warnings, 0 errors, 0 skipped") {
		t.Errorf("expected summary line, got:\n%s", output)
	}
}

func TestRenderHuman_WithRunnerContext(t *testing.T) {
	var buf bytes.Buffer
	report := &models.AuditReport{
		Audit: "lab", Status: models.StatusPass,
		Runner: models.RunnerContext{
			LocalIPs: []string{"192.168.1.10", "10.0.0.5"},
			Networks: []string{"lan", "dmz"},
		},
		Findings: []models.CheckResult{
			{CheckType: "subnet_discovery", Status: models.StatusPass, Summary: "ok"},
		},
	}
	RenderHuman(&buf, report)

	output := buf.String()
	if !strings.Contains(output, "Running from: 192.168.1.10, 10.0.0.5") {
		t.Error("expected Running from line with IPs")
	}
	if !strings.Contains(output, "(inside: lan, dmz)") {
		t.Error("expected inside networks annotation")
	}
	if !strings.Contains(output, "--- 1 assertions, evaluated from this vantage point ---") {
		t.Error("expected assertion count separator")
	}
}

func TestRenderHuman_OutsideAnyNetwork(t *testing.T) {
	var buf bytes.Buffer
	report := &models.AuditReport{
		Audit: "lab", Status: models.StatusWarn,
		Runner: models.RunnerContext{
			LocalIPs: []string{"172.16.0.99"},
			Networks: []string{},
		},
		Findings: []models.CheckResult{
			{CheckType: "subnet_discovery", Status: models.StatusWarn, Summary: "0 hosts"},
		},
	}
	RenderHuman(&buf, report)

	output := buf.String()
	if !strings.Contains(output, "outside any spec network") {
		t.Error("expected 'outside any spec network' warning")
	}
}

func TestRenderHuman_AllStatusTags(t *testing.T) {
	var buf bytes.Buffer
	report := &models.AuditReport{
		Audit: "all", Status: models.StatusFail,
		Summary: models.ReportSummary{Pass: 1, Fail: 1, Warn: 1, Error: 1, Skip: 1},
		Findings: []models.CheckResult{
			{CheckType: "subnet_discovery", Status: models.StatusPass, Summary: "pass check"},
			{CheckType: "isolation", Status: models.StatusFail, Summary: "fail check"},
			{CheckType: "dns_check", Status: models.StatusWarn, Summary: "warn check"},
			{CheckType: "port_check", Status: models.StatusError, Summary: "error check"},
			{CheckType: "route_check", Status: models.StatusSkip, Summary: "skip check"},
		},
	}
	RenderHuman(&buf, report)

	output := buf.String()
	if !strings.Contains(output, "[PASS] subnet_discovery: pass check") {
		t.Error("expected [PASS] tag")
	}
	if !strings.Contains(output, "[FAIL] isolation: fail check") {
		t.Error("expected [FAIL] tag")
	}
	if !strings.Contains(output, "[WARN] dns_check: warn check") {
		t.Error("expected [WARN] tag")
	}
	if !strings.Contains(output, "[ERR ] port_check: error check") {
		t.Error("expected [ERR ] tag")
	}
	if !strings.Contains(output, "[SKIP] route_check: skip check") {
		t.Error("expected [SKIP] tag")
	}
}

func TestRenderHuman_WithViolations(t *testing.T) {
	var buf bytes.Buffer
	report := &models.AuditReport{
		Audit: "lab", Status: models.StatusFail,
		Findings: []models.CheckResult{
			{CheckType: "subnet_discovery", Status: models.StatusFail, Summary: "host count mismatch",
				Violations: []string{"expected max 10, found 25", "unexpected host 10.0.0.99"}},
		},
	}
	RenderHuman(&buf, report)

	output := buf.String()
	if !strings.Contains(output, "↳ expected max 10, found 25") {
		t.Error("expected first violation")
	}
	if !strings.Contains(output, "↳ unexpected host 10.0.0.99") {
		t.Error("expected second violation")
	}
}

func TestRenderHuman_WithEvidence(t *testing.T) {
	var buf bytes.Buffer
	report := &models.AuditReport{
		Audit: "lab", Status: models.StatusPass,
		Findings: []models.CheckResult{
			{CheckType: "route_check", Status: models.StatusPass, Summary: "route verified",
				Evidence: []string{"Destination: 8.8.8.8", "Gateway: 192.168.1.1"}},
		},
	}
	RenderHuman(&buf, report)

	output := buf.String()
	if !strings.Contains(output, "• Destination: 8.8.8.8") {
		t.Error("expected evidence bullet 1")
	}
	if !strings.Contains(output, "• Gateway: 192.168.1.1") {
		t.Error("expected evidence bullet 2")
	}
}

func TestRenderHuman_MultiLineEvidence(t *testing.T) {
	var buf bytes.Buffer
	report := &models.AuditReport{
		Audit: "lab", Status: models.StatusPass,
		Findings: []models.CheckResult{
			{CheckType: "subnet_discovery", Status: models.StatusPass, Summary: "scan complete",
				Evidence: []string{"nmap output:\nhost1: 10.0.0.1\nhost2: 10.0.0.2"}},
		},
	}
	RenderHuman(&buf, report)

	output := buf.String()
	if !strings.Contains(output, "• nmap output:") {
		t.Error("expected first evidence line")
	}
	if !strings.Contains(output, "• host1: 10.0.0.1") {
		t.Error("expected second evidence line from multi-line blob")
	}
	if !strings.Contains(output, "• host2: 10.0.0.2") {
		t.Error("expected third evidence line from multi-line blob")
	}
}

func TestRenderHuman_NoRunnerContext(t *testing.T) {
	var buf bytes.Buffer
	report := &models.AuditReport{
		Audit: "simple", Status: models.StatusPass,
		Summary: models.ReportSummary{Pass: 1},
		Findings: []models.CheckResult{
			{CheckType: "dns_check", Status: models.StatusPass, Summary: "ok"},
		},
	}
	RenderHuman(&buf, report)

	output := buf.String()
	if strings.Contains(output, "Running from:") {
		t.Error("should not have Running from when no LocalIPs")
	}
	if strings.Contains(output, "outside any spec network") {
		t.Error("should not have outside message when no LocalIPs")
	}
	if strings.Contains(output, "--- 1 assertions") {
		t.Error("should not have assertion count separator when no LocalIPs")
	}
}

func TestRenderHuman_EmptyFindings(t *testing.T) {
	var buf bytes.Buffer
	report := &models.AuditReport{
		Audit: "empty", Status: models.StatusPass,
		Summary: models.ReportSummary{},
	}
	RenderHuman(&buf, report)

	output := buf.String()
	if !strings.Contains(output, "Site: empty") {
		t.Error("expected site name even with no findings")
	}
	if !strings.Contains(output, "Summary: 0 passed, 0 failed, 0 warnings, 0 errors, 0 skipped") {
		t.Error("expected zero summary line")
	}
}

func TestRenderHuman_StatusLabelFromReport(t *testing.T) {
	for _, st := range []models.Status{models.StatusPass, models.StatusFail, models.StatusWarn, models.StatusError, models.StatusSkip} {
		t.Run(string(st), func(t *testing.T) {
			var buf bytes.Buffer
			report := &models.AuditReport{Audit: "test", Status: st}
			RenderHuman(&buf, report)
			expected := strings.ToUpper(string(st))
			if !strings.Contains(buf.String(), "Status: "+expected) {
				t.Errorf("expected 'Status: %s', got: %s", expected, buf.String())
			}
		})
	}
}

func TestRenderHuman_CRLFInEvidence(t *testing.T) {
	var buf bytes.Buffer
	report := &models.AuditReport{
		Audit: "lab", Status: models.StatusPass,
		Findings: []models.CheckResult{
			{CheckType: "route_check", Status: models.StatusPass, Summary: "ok",
				Evidence: []string{"line1\r\nline2\r\n"}},
		},
	}
	RenderHuman(&buf, report)

	output := buf.String()
	if !strings.Contains(output, "• line1") {
		t.Error("expected line1 after CRLF handling")
	}
	if !strings.Contains(output, "• line2") {
		t.Error("expected line2 after CRLF handling")
	}
}

func TestRenderHuman_SkipsEmptyEvidenceLines(t *testing.T) {
	var buf bytes.Buffer
	report := &models.AuditReport{
		Audit: "lab", Status: models.StatusPass,
		Findings: []models.CheckResult{
			{CheckType: "route_check", Status: models.StatusPass, Summary: "ok",
				Evidence: []string{"line1\n\nline3\n"}},
		},
	}
	RenderHuman(&buf, report)

	output := buf.String()
	if !strings.Contains(output, "• line1") {
		t.Error("expected line1")
	}
	if !strings.Contains(output, "• line3") {
		t.Error("expected line3")
	}
	// Count bullets — should be exactly 2 (empty line skipped)
	bulletCount := strings.Count(output, "• ")
	if bulletCount != 2 {
		t.Errorf("expected 2 bullets (empty line skipped), got %d", bulletCount)
	}
}

// =====================================================================
// RenderResultJSON
// =====================================================================

func TestRenderResultJSON_Basic(t *testing.T) {
	var buf bytes.Buffer
	result := &models.CheckResult{
		Tool: "nmap", CheckType: "subnet_discovery", Runner: "local", Target: "10.0.0.0/24",
		Status: models.StatusPass, Summary: "5 hosts found",
		Observed: map[string]interface{}{"total": 5},
		Expected: map[string]interface{}{"total": 5},
	}
	result.Finish()

	err := RenderResultJSON(&buf, result)
	if err != nil {
		t.Fatalf("RenderResultJSON error: %v", err)
	}

	var decoded models.CheckResult
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, buf.String())
	}
	if decoded.Tool != "nmap" {
		t.Errorf("expected tool 'nmap', got %q", decoded.Tool)
	}
	if decoded.CheckType != "subnet_discovery" {
		t.Errorf("expected check_type 'subnet_discovery', got %q", decoded.CheckType)
	}
	if decoded.Status != models.StatusPass {
		t.Errorf("expected status pass, got %s", decoded.Status)
	}
	if decoded.Target != "10.0.0.0/24" {
		t.Errorf("expected target '10.0.0.0/24', got %q", decoded.Target)
	}
}

func TestRenderResultJSON_WithViolations(t *testing.T) {
	var buf bytes.Buffer
	result := &models.CheckResult{
		Tool: "nmap", CheckType: "isolation", Status: models.StatusFail,
		Summary:    "isolation violation",
		Violations: []string{"expected deny, got reachable"},
		Evidence:   []string{"ping 10.0.1.1: 64 bytes"},
	}
	err := RenderResultJSON(&buf, result)
	if err != nil {
		t.Fatalf("RenderResultJSON error: %v", err)
	}

	var decoded models.CheckResult
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if len(decoded.Violations) != 1 {
		t.Errorf("expected 1 violation, got %d", len(decoded.Violations))
	}
	if len(decoded.Evidence) != 1 {
		t.Errorf("expected 1 evidence, got %d", len(decoded.Evidence))
	}
}

func TestRenderResultJSON_EmptyResult(t *testing.T) {
	var buf bytes.Buffer
	result := &models.CheckResult{}
	err := RenderResultJSON(&buf, result)
	if err != nil {
		t.Fatalf("RenderResultJSON error with empty result: %v", err)
	}

	output := buf.String()
	// JSON null is valid for zero-value Status — no assertion needed
	_ = output
	// Should still produce valid JSON
	var decoded map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

// =====================================================================
// RenderResultHuman
// =====================================================================

func TestRenderResultHuman_Basic(t *testing.T) {
	var buf bytes.Buffer
	result := &models.CheckResult{
		Tool: "nmap", CheckType: "subnet_discovery", Status: models.StatusPass,
		Summary: "5 hosts found in 10.0.0.0/24",
	}
	RenderResultHuman(&buf, result)

	output := buf.String()
	if !strings.Contains(output, "[PASS] subnet_discovery: 5 hosts found in 10.0.0.0/24") {
		t.Errorf("expected finding line, got:\n%s", output)
	}
}

func TestRenderResultHuman_WithViolations(t *testing.T) {
	var buf bytes.Buffer
	result := &models.CheckResult{
		Tool: "nmap", CheckType: "port_check", Status: models.StatusFail,
		Summary:    "port 443 not open",
		Violations: []string{"port 443: expected open, got closed"},
	}
	RenderResultHuman(&buf, result)

	output := buf.String()
	if !strings.Contains(output, "[FAIL] port_check: port 443 not open") {
		t.Error("expected check line")
	}
	if !strings.Contains(output, "↳ port 443: expected open, got closed") {
		t.Error("expected violation line")
	}
}

func TestRenderResultHuman_WithEvidence(t *testing.T) {
	var buf bytes.Buffer
	result := &models.CheckResult{
		Tool: "dig", CheckType: "dns_check", Status: models.StatusPass,
		Summary:  "resolved ok",
		Evidence: []string{"nslookup: example.com -> 93.184.216.34"},
	}
	RenderResultHuman(&buf, result)

	output := buf.String()
	if !strings.Contains(output, "• nslookup: example.com -> 93.184.216.34") {
		t.Error("expected evidence line")
	}
}

func TestRenderResultHuman_AllStatuses(t *testing.T) {
	for _, st := range []models.Status{models.StatusPass, models.StatusFail, models.StatusWarn, models.StatusError, models.StatusSkip} {
		t.Run(string(st), func(t *testing.T) {
			var buf bytes.Buffer
			result := &models.CheckResult{CheckType: "test_check", Status: st, Summary: "summary"}
			RenderResultHuman(&buf, result)
			tag := statusTag(st)
			if !strings.Contains(buf.String(), tag) {
				t.Errorf("expected tag %s in output: %s", tag, buf.String())
			}
		})
	}
}

// =====================================================================
// RenderRecommendations
// =====================================================================

func TestRenderRecommendations_SingleRecommendation(t *testing.T) {
	var buf bytes.Buffer
	recs := []recommendations.Recommendation{
		{
			Priority:    1,
			Category:    "vantage_point",
			Title:       "Wrong vantage point",
			Description: "You are running from outside the target network.",
			Remediation: "Add a probe in the target VLAN.",
			Affected:    []string{"subnet_discovery:guest"},
		},
	}
	RenderRecommendations(&buf, recs)

	output := buf.String()
	if !strings.Contains(output, "--- What I Think Is Going On ---") {
		t.Error("expected header")
	}
	if !strings.Contains(output, "[1] Wrong vantage point (vantage_point)") {
		t.Error("expected priority, title, and category")
	}
	if !strings.Contains(output, "You are running from outside the target network.") {
		t.Error("expected description")
	}
	if !strings.Contains(output, "Fix: Add a probe in the target VLAN.") {
		t.Error("expected remediation")
	}
	if !strings.Contains(output, "Affected: subnet_discovery:guest") {
		t.Error("expected affected (single)")
	}
}

func TestRenderRecommendations_MultipleRecommendations(t *testing.T) {
	var buf bytes.Buffer
	recs := []recommendations.Recommendation{
		{
			Priority: 1, Category: "vantage_point",
			Title: "Wrong vantage point", Description: "desc1", Remediation: "fix1",
			Affected: []string{"check1"},
		},
		{
			Priority: 2, Category: "isolation_breach",
			Title: "Isolation breach", Description: "desc2", Remediation: "fix2",
			Affected: []string{"check2"},
		},
	}
	RenderRecommendations(&buf, recs)

	output := buf.String()
	if !strings.Contains(output, "[1] Wrong vantage point") {
		t.Error("expected first recommendation")
	}
	if !strings.Contains(output, "[2] Isolation breach") {
		t.Error("expected second recommendation")
	}
}

func TestRenderRecommendations_Empty(t *testing.T) {
	var buf bytes.Buffer
	RenderRecommendations(&buf, nil)
	output := buf.String()
	if output != "" {
		t.Errorf("expected empty output for nil recs, got: %s", output)
	}

	var buf2 bytes.Buffer
	RenderRecommendations(&buf2, []recommendations.Recommendation{})
	if buf2.String() != "" {
		t.Errorf("expected empty output for empty recs, got: %s", buf2.String())
	}
}

func TestRenderRecommendations_WithSpecPatch(t *testing.T) {
	var buf bytes.Buffer
	recs := []recommendations.Recommendation{
		{
			Priority: 1, Category: "vantage_point",
			Title: "Wrong vantage point", Description: "desc", Remediation: "fix",
			SpecPatch: "+ probes:\n+   - name: guest-probe\n+     host: 10.0.2.1",
		},
	}
	RenderRecommendations(&buf, recs)

	output := buf.String()
	if !strings.Contains(output, "Suggested spec addition:") {
		t.Error("expected spec patch header")
	}
	if !strings.Contains(output, "+ probes:") {
		t.Error("expected spec patch line 1")
	}
	if !strings.Contains(output, "+   - name: guest-probe") {
		t.Error("expected spec patch line 2")
	}
}

func TestRenderRecommendations_AffectedMultiple(t *testing.T) {
	var buf bytes.Buffer
	// 2 affected items — inline comma-separated
	recs := []recommendations.Recommendation{
		{
			Priority: 1, Category: "isolation_breach",
			Title: "Breach", Description: "desc", Remediation: "fix",
			Affected: []string{"guest->lan", "iot->lan"},
		},
	}
	RenderRecommendations(&buf, recs)
	output := buf.String()
	if !strings.Contains(output, "Affected (2): guest->lan, iot->lan") {
		t.Errorf("expected inline affected list, got:\n%s", output)
	}
}

func TestRenderRecommendations_AffectedFourItems(t *testing.T) {
	var buf bytes.Buffer
	recs := []recommendations.Recommendation{
		{
			Priority: 1, Category: "service_down",
			Title: "Down", Description: "desc", Remediation: "fix",
			Affected: []string{"a", "b", "c", "d"},
		},
	}
	RenderRecommendations(&buf, recs)
	output := buf.String()
	if !strings.Contains(output, "Affected (4): a, b, c, d") {
		t.Errorf("expected 4-item inline list, got:\n%s", output)
	}
}

func TestRenderRecommendations_AffectedFivePlusItems(t *testing.T) {
	var buf bytes.Buffer
	recs := []recommendations.Recommendation{
		{
			Priority: 1, Category: "service_down",
			Title: "Down", Description: "desc", Remediation: "fix",
			Affected: []string{"a", "b", "c", "d", "e"},
		},
	}
	RenderRecommendations(&buf, recs)
	output := buf.String()
	if !strings.Contains(output, "Affected (5 checks):") {
		t.Errorf("expected bulleted affected list for 5+ items, got:\n%s", output)
	}
	if !strings.Contains(output, "• a") {
		t.Error("expected bullet for 'a'")
	}
	if !strings.Contains(output, "• e") {
		t.Error("expected bullet for 'e'")
	}
}

func TestRenderRecommendations_NoAffected(t *testing.T) {
	var buf bytes.Buffer
	recs := []recommendations.Recommendation{
		{
			Priority: 1, Category: "generic",
			Title: "Something", Description: "desc", Remediation: "fix",
		},
	}
	RenderRecommendations(&buf, recs)
	output := buf.String()
	if strings.Contains(output, "Affected:") {
		t.Error("should not show Affected when empty")
	}
}

func TestRenderRecommendations_SpecPatchSkipsEmptyLines(t *testing.T) {
	var buf bytes.Buffer
	recs := []recommendations.Recommendation{
		{
			Priority: 1, Category: "vantage_point",
			Title: "Test", Description: "desc", Remediation: "fix",
			SpecPatch: "line1\n\nline3\n",
		},
	}
	RenderRecommendations(&buf, recs)
	output := buf.String()
	if !strings.Contains(output, "line1") {
		t.Error("expected line1 in spec patch")
	}
	if !strings.Contains(output, "line3") {
		t.Error("expected line3 in spec patch")
	}
	// Empty lines should be skipped — count how many spec patch lines
	lines := strings.Split(output, "\n")
	specPatchLines := 0
	for _, l := range lines {
		if strings.HasPrefix(l, "        ") && !strings.Contains(l, "Suggested") {
			specPatchLines++
		}
	}
	if specPatchLines != 2 {
		t.Errorf("expected 2 spec patch lines (empty skipped), got %d", specPatchLines)
	}
}

// =====================================================================
// statusTag (private function tested via public APIs)
// =====================================================================

func TestStatusTag_AllStatuses(t *testing.T) {
	tests := []struct {
		status models.Status
		want   string
	}{
		{models.StatusPass, "[PASS]"},
		{models.StatusFail, "[FAIL]"},
		{models.StatusWarn, "[WARN]"},
		{models.StatusError, "[ERR ]"},
		{models.StatusSkip, "[SKIP]"},
		{"unknown_status", "[????]"},
		{"", "[????]"},
	}
	for _, tt := range tests {
		t.Run(string(tt.status), func(t *testing.T) {
			got := statusTag(tt.status)
			if got != tt.want {
				t.Errorf("statusTag(%q) = %q, want %q", tt.status, got, tt.want)
			}
		})
	}
}

// =====================================================================
// Integration: RenderHuman end-to-end with complex report
// =====================================================================

func TestRenderHuman_ComplexReport(t *testing.T) {
	var buf bytes.Buffer
	report := &models.AuditReport{
		Audit: "enterprise", Status: models.StatusFail,
		Summary: models.ReportSummary{Pass: 3, Fail: 2, Warn: 1, Error: 1, Skip: 1},
		Runner: models.RunnerContext{
			LocalIPs: []string{"192.168.1.50"},
			Networks: []string{"corporate"},
		},
		Findings: []models.CheckResult{
			{
				CheckType: "subnet_discovery", Status: models.StatusPass, Summary: "15 hosts in corporate",
				Observed: map[string]interface{}{"total": 15},
				Evidence: []string{"nmap -sn 192.168.1.0/24"},
			},
			{
				CheckType: "isolation", Status: models.StatusFail, Summary: "guest can reach corporate",
				Violations: []string{"expected deny, got reachable"},
				Evidence:   []string{"ping 192.168.1.1: 64 bytes reply"},
			},
			{
				CheckType: "dns_check", Status: models.StatusWarn, Summary: "slow DNS response",
				Evidence: []string{"query time: 2500ms"},
			},
			{
				CheckType: "port_check", Status: models.StatusError, Summary: "nmap timed out",
			},
			{
				CheckType: "route_check", Status: models.StatusSkip, Summary: "skipped — no target",
			},
		},
	}
	RenderHuman(&buf, report)

	output := buf.String()

	// Header
	if !strings.Contains(output, "Site: enterprise") {
		t.Error("expected site name")
	}
	if !strings.Contains(output, "Status: FAIL") {
		t.Error("expected FAIL status")
	}

	// Runner context
	if !strings.Contains(output, "Running from: 192.168.1.50") {
		t.Error("expected Running from")
	}
	if !strings.Contains(output, "inside: corporate") {
		t.Error("expected inside network")
	}
	if !strings.Contains(output, "--- 5 assertions") {
		t.Error("expected assertion count")
	}

	// Findings
	if !strings.Contains(output, "[PASS] subnet_discovery: 15 hosts in corporate") {
		t.Error("expected pass finding")
	}
	if !strings.Contains(output, "[FAIL] isolation: guest can reach corporate") {
		t.Error("expected fail finding")
	}
	if !strings.Contains(output, "↳ expected deny, got reachable") {
		t.Error("expected violation")
	}
	if !strings.Contains(output, "• ping 192.168.1.1: 64 bytes reply") {
		t.Error("expected evidence")
	}
	if !strings.Contains(output, "[WARN] dns_check: slow DNS response") {
		t.Error("expected warn finding")
	}
	if !strings.Contains(output, "[ERR ] port_check: nmap timed out") {
		t.Error("expected error finding")
	}
	if !strings.Contains(output, "[SKIP] route_check: skipped — no target") {
		t.Error("expected skip finding")
	}

	// Summary
	if !strings.Contains(output, "Summary: 3 passed, 2 failed, 1 warnings, 1 errors, 1 skipped") {
		t.Errorf("expected summary line, got:\n%s", output)
	}
}

func TestRenderHuman_CRLFInEvidence_BulletCount(t *testing.T) {
	var buf bytes.Buffer
	report := &models.AuditReport{
		Audit: "lab", Status: models.StatusPass,
		Findings: []models.CheckResult{
			{CheckType: "test", Status: models.StatusPass, Summary: "ok",
				Evidence: []string{"line1\r\nline2\r\n"}},
		},
	}
	RenderHuman(&buf, report)
	output := buf.String()
	bulletCount := strings.Count(output, "• ")
	if bulletCount != 2 {
		t.Errorf("expected 2 bullets from CRLF evidence, got %d: %s", bulletCount, output)
	}
}
