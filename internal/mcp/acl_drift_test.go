package mcp

import (
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/report"
)

func TestOmitControllerACLNames(t *testing.T) {
	const controllerName = "private controller label"
	original := &models.AuditReport{Findings: []models.CheckResult{
		{CheckType: "acl_drift", Status: models.StatusWarn, Observed: map[string]any{
			"live_but_undeclared": []string{controllerName},
			"declared_but_absent": []string{"declared-rule"},
		}},
		{CheckType: "isolation", Observed: map[string]any{"source_network": "trusted"}},
	}}
	output := toJSON(report.OmitControllerACLNames(original))
	if !strings.Contains(toJSON(original), controllerName) {
		t.Fatal("projection unexpectedly changed the original audit report")
	}
	if strings.Contains(output, controllerName) {
		t.Fatalf("controller ACL label exposed in MCP result: %s", output)
	}
	for _, want := range []string{`"live_but_undeclared_count": 1`, `"declared-rule"`, `"source_network": "trusted"`} {
		if !strings.Contains(output, want) {
			t.Errorf("MCP result missing %s: %s", want, output)
		}
	}
}
