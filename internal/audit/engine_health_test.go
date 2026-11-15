package audit

import (
	"context"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/backends"
	"github.com/jpvelasco/nyx/internal/backends/health"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
)

// --- runNetworkHealth ---

func TestRunNetworkHealth_PingCheck(t *testing.T) {
	r := models.NewCheckResult("ping", "network_health", "system", "10.0.0.1")
	r.Status = models.StatusPass
	r.Finish()

	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "network_health", Target: "10.0.0.1"}},
	}
	mock := &backends.MockBackend{PingCheckResult: r}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runNetworkHealth(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass, got %s", result.Status)
	}
}

// TestRunNetworkHealth_DeadHostFail verifies a Fail verdict from the backend
// (host down, 100% loss) flows through the engine untouched — it must not be
// converted into an engine error or overwritten (regression: dead targets
// used to surface as Error / exit 2, and expect_loss_pct: 0 could pass).
func TestRunNetworkHealth_DeadHostFail(t *testing.T) {
	r := models.NewCheckResult("ping", "network_health", "system", "10.0.0.1")
	r.Status = models.StatusFail
	r.Observed = map[string]interface{}{"loss_pct": float64(100), "sent": 3, "received": 0}
	r.Violations = []string{"100% packet loss — host unreachable"}
	r.Finish()

	tests := []struct {
		name      string
		assertion intent.Assertion
	}{
		{name: "no thresholds", assertion: intent.Assertion{Type: "network_health", Target: "10.0.0.1"}},
		{name: "zero loss threshold", assertion: intent.Assertion{Type: "network_health", Target: "10.0.0.1", ExpectLossPct: 0}},
		{name: "latency threshold", assertion: intent.Assertion{Type: "network_health", Target: "10.0.0.1", ExpectLatencyMs: 100}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := &intent.Spec{
				Version: 1, Site: "test",
				Assertions: []intent.Assertion{tt.assertion},
			}
			mock := &backends.MockBackend{PingCheckResult: r, LatencyResult: r}
			eng := NewEngine(spec)
			eng.Backend = mock
			result, err := eng.runNetworkHealth(context.Background(), spec.Assertions[0])
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Status != models.StatusFail {
				t.Errorf("expected fail for dead host, got %s: %s", result.Status, result.Summary)
			}
		})
	}
}

func TestRunNetworkHealth_LatencyAndLoss(t *testing.T) {
	r := models.NewCheckResult("ping", "network_health", "system", "10.0.0.1")
	r.Status = models.StatusPass
	r.Finish()

	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "network_health", Target: "10.0.0.1", ExpectLatencyMs: 100}},
	}
	mock := &backends.MockBackend{LatencyResult: r}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runNetworkHealth(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass, got %s", result.Status)
	}
}

func TestRunNetworkHealth_MTUPass(t *testing.T) {
	r := models.NewCheckResult("ping", "network_health", "system", "10.0.0.1")
	r.Status = models.StatusPass
	r.Finish()

	mtuR := models.NewCheckResult("ping", "network_health", "system", "10.0.0.1")
	mtuR.Status = models.StatusPass
	mtuR.Observed = map[string]interface{}{"mtu": 1500}
	mtuR.Evidence = []string{"MTU probe ok"}
	mtuR.Finish()

	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "network_health", Target: "10.0.0.1", ExpectMTU: 1500}},
	}
	mock := &backends.MockBackend{PingCheckResult: r, PingCheckStats: &health.PingStats{}, MTUResult: mtuR}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runNetworkHealth(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass with MTU, got %s", result.Status)
	}
	if result.Observed["mtu"] != 1500 {
		t.Errorf("expected MTU in observed, got %v", result.Observed["mtu"])
	}
}

func TestRunNetworkHealth_MTUWarn(t *testing.T) {
	r := models.NewCheckResult("ping", "network_health", "system", "10.0.0.1")
	r.Status = models.StatusPass
	r.Finish()

	mtuR := models.NewCheckResult("ping", "network_health", "system", "10.0.0.1")
	mtuR.Status = models.StatusWarn
	mtuR.Evidence = []string{"MTU slightly low"}
	mtuR.Finish()

	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "network_health", Target: "10.0.0.1", ExpectMTU: 1500}},
	}
	mock := &backends.MockBackend{PingCheckResult: r, PingCheckStats: &health.PingStats{}, MTUResult: mtuR}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runNetworkHealth(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusWarn {
		t.Errorf("expected warn for MTU, got %s", result.Status)
	}
}

func TestRunNetworkHealth_MTUFail(t *testing.T) {
	r := models.NewCheckResult("ping", "network_health", "system", "10.0.0.1")
	r.Status = models.StatusPass
	r.Finish()

	mtuR := models.NewCheckResult("ping", "network_health", "system", "10.0.0.1")
	mtuR.Status = models.StatusFail
	mtuR.Summary = "MTU too low"
	mtuR.Evidence = []string{"MTU too low"}
	mtuR.Finish()

	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "network_health", Target: "10.0.0.1", ExpectMTU: 1500}},
	}
	mock := &backends.MockBackend{PingCheckResult: r, PingCheckStats: &health.PingStats{}, MTUResult: mtuR}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runNetworkHealth(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusFail {
		t.Errorf("expected fail for MTU, got %s", result.Status)
	}
}

// TestRunNetworkHealth_MTUUnmeasurableIsError pins that a health assertion
// whose MTU probe could not confirm any size (unreachable or canceled)
// never reads as PASS: the MTU result's error status escalates the
// assertion verdict (repro of the invented-576 PASS in #178).
func TestRunNetworkHealth_MTUUnmeasurableIsError(t *testing.T) {
	spec := &intent.Spec{
		Version: 1,
		Site:    "test",
		Assertions: []intent.Assertion{
			{Type: "network_health", Target: "10.0.40.1", ExpectMTU: 1500},
		},
	}

	pingPass := models.NewCheckResult("ping", "network_health", "system", "10.0.40.1")
	pingPass.Status = models.StatusPass
	pingPass.Summary = "health ok"
	pingPass.Observed = map[string]interface{}{"loss_pct": 0.0}

	mtuErrResult := models.NewCheckResult("ping", "network_health", "system", "10.0.40.1")
	mtuErrResult.Status = models.StatusError
	mtuErrResult.Summary = "MTU could not be determined - no probe size succeeded"
	mtuErrResult.Observed = map[string]interface{}{"mtu": "unknown"}
	mtuErrResult.Evidence = append(mtuErrResult.Evidence, "MTU probe: 1500 failed", "MTU probe: 576 failed")

	mock := &backends.MockBackend{
		PingCheckResult: pingPass,
		MTUResult:       mtuErrResult,
	}

	eng := NewEngine(spec)
	eng.Backend = mock
	report, err := eng.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(report.Findings))
	}
	finding := report.Findings[0]
	if finding.Status != models.StatusError {
		t.Errorf("health assertion with unmeasurable MTU = %s, want error", finding.Status)
	}
	if finding.Summary == "" {
		t.Error("finding should keep the health summary")
	}
	found := false
	for _, v := range finding.Violations {
		if strings.Contains(v, "MTU could not be determined") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an MTU violation, got %v", finding.Violations)
	}
	if mtu, ok := finding.Observed["mtu"]; !ok || mtu != "unknown" {
		t.Errorf("observed mtu = %v, want \"unknown\"", finding.Observed["mtu"])
	}
}
