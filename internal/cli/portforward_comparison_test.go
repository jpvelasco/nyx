package cli

import (
	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/service"
	"strings"
	"testing"
)

func TestPortForwardRenderCandidateComparison(t *testing.T) {
	plan := &service.PortForwardPlan{Provider: "omada", Outcome: "refused", Comparison: &providers.NatComparison{Observation: "review matching rules"}}
	got := captureStdout(func() { renderPortForwardPlan(plan) })
	if !strings.Contains(got, "NAT comparison: review matching rules (0 candidates)") || !strings.Contains(got, "outcome: refused") {
		t.Fatalf("rendered plan %s", got)
	}
}
