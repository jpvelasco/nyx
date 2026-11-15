package audit

import (
	"context"
	"testing"

	"github.com/jpvelasco/nyx/internal/backends"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
)

// --- runPortCheck ---

func TestRunPortCheck_AllOpen(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "port_check", Target: "10.0.0.1", Ports: []int{80, 443}, Expect: "open"}},
	}
	mock := &backends.MockBackend{
		PortScanResult: mockPortScanResult([]int{80, 443}, "open"),
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runPortCheck(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass, got %s: %s", result.Status, result.Summary)
	}
	// The ports expectation must be populated for drift-key disambiguation.
	if result.Expected["ports"] == nil {
		t.Error("expected Expected[\"ports\"] to be set for drift disambiguation")
	}
}

func TestRunPortCheck_MixedStates(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "port_check", Target: "10.0.0.1", Ports: []int{80, 443}, Expect: "open"}},
	}
	r := models.NewCheckResult("nmap", "port_check", "nmap", "10.0.0.1")
	r.Status = models.StatusPass
	r.Observed = map[string]interface{}{
		"ports": []interface{}{
			map[string]interface{}{"port": float64(80), "protocol": "tcp", "state": "open"},
			map[string]interface{}{"port": float64(443), "protocol": "tcp", "state": "filtered"},
		},
	}
	r.Finish()
	mock := &backends.MockBackend{PortScanResult: r}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runPortCheck(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusFail {
		t.Errorf("expected fail for mismatched port, got %s", result.Status)
	}
}

func TestRunPortCheck_DefaultProtocol(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "port_check", Target: "10.0.0.1", Ports: []int{80}, Expect: "open"}},
	}
	mock := &backends.MockBackend{
		PortScanResult: mockPortScanResult([]int{80}, "open"),
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runPortCheck(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass, got %s", result.Status)
	}
}

// --- runPortCheck closed/filtered semantics (#116) ---

func TestRunPortCheck_ClosedAcceptsFiltered(t *testing.T) {
	// nmap scans with --open, so closed ports are absent from the output and
	// the parser tags them "filtered". expect: closed must PASS for a
	// not-open port — previously it always failed with "got filtered".
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "port_check", Target: "10.0.0.1", Ports: []int{8080}, Expect: "closed"}},
	}
	mock := &backends.MockBackend{
		PortScanResult: mockPortScanResult([]int{8080}, "filtered"),
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runPortCheck(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass (not-open port with expect closed), got %s: %s", result.Status, result.Summary)
	}
}

func TestRunPortCheck_ClosedViolatedWhenOpen(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "port_check", Target: "10.0.0.1", Ports: []int{8080}, Expect: "closed"}},
	}
	mock := &backends.MockBackend{
		PortScanResult: mockPortScanResult([]int{8080}, "open"),
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runPortCheck(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusFail {
		t.Errorf("expected fail (open port with expect closed), got %s: %s", result.Status, result.Summary)
	}
}

func TestRunPortCheck_OpenFailsWhenFiltered(t *testing.T) {
	// A port absent from --open output must not satisfy expect: open.
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "port_check", Target: "10.0.0.1", Ports: []int{8080}, Expect: "open"}},
	}
	mock := &backends.MockBackend{
		PortScanResult: mockPortScanResult([]int{8080}, "filtered"),
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runPortCheck(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusFail {
		t.Errorf("expected fail (filtered port with expect open), got %s: %s", result.Status, result.Summary)
	}
}

func TestRunPortCheck_OpenPassesWhenOpen(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "port_check", Target: "10.0.0.1", Ports: []int{80}, Expect: "open"}},
	}
	mock := &backends.MockBackend{
		PortScanResult: mockPortScanResult([]int{80}, "open"),
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runPortCheck(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass (open port with expect open), got %s: %s", result.Status, result.Summary)
	}
}
