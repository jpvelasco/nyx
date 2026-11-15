package audit

import (
	"context"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/backends"
	"github.com/jpvelasco/nyx/internal/backends/system"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
)

// --- runIsolation ---

func TestRunIsolation_DenyConfirmed(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks: []intent.Network{
			{Name: "fromnet", CIDR: "10.0.0.0/24", Gateway: "10.0.0.1", Zone: "fromzone"},
			{Name: "tonet", CIDR: "10.0.1.0/24", Gateway: "10.0.1.1", Zone: "tozone"},
		},
		Assertions: []intent.Assertion{{Type: "isolation", From: "fromzone", To: "tozone", Expect: "deny"}},
	}
	mock := &backends.MockBackend{
		PingResult: &system.PingResult{Reachable: false},
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	eng.runnerCtx = models.RunnerContext{Networks: []string{"fromnet"}}
	result, err := eng.runIsolation(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass when runner is in from zone and all blocked, got %s: %s", result.Status, result.Summary)
	}
}

func TestRunIsolation_AllowConfirmed(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks: []intent.Network{
			{Name: "fromnet", CIDR: "10.0.0.0/24", Gateway: "10.0.0.1", Zone: "fromzone"},
			{Name: "tonet", CIDR: "10.0.1.0/24", Gateway: "10.0.1.1", Zone: "tozone"},
		},
		Assertions: []intent.Assertion{{Type: "isolation", From: "fromzone", To: "tozone", Expect: "allow"}},
	}
	mock := &backends.MockBackend{
		PingResult: &system.PingResult{Reachable: true},
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	eng.runnerCtx = models.RunnerContext{Networks: []string{"fromnet"}}
	result, err := eng.runIsolation(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass, got %s: %s", result.Status, result.Summary)
	}
}

// TestRunIsolation_VantageGuard verifies that every verdict is downgraded to
// Warn when the runner is outside the source zone — reachability observed
// from the wrong vantage point is never definitive.
func TestRunIsolation_VantageGuard(t *testing.T) {
	tests := []struct {
		name        string
		expect      string
		reachable   bool
		wantSummary string
	}{
		{name: "deny blocked", expect: "deny", reachable: false, wantSummary: "isolation unconfirmed"},
		{name: "deny reachable", expect: "deny", reachable: true, wantSummary: "isolation unconfirmed"},
		{name: "allow reachable", expect: "allow", reachable: true, wantSummary: "connectivity unconfirmed"},
		{name: "allow blocked", expect: "allow", reachable: false, wantSummary: "connectivity unconfirmed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := &intent.Spec{
				Version: 1, Site: "test",
				Networks: []intent.Network{
					{Name: "fromnet", CIDR: "10.0.0.0/24", Gateway: "10.0.0.1", Zone: "fromzone"},
					{Name: "tonet", CIDR: "10.0.1.0/24", Gateway: "10.0.1.1", Zone: "tozone"},
				},
				Assertions: []intent.Assertion{{Type: "isolation", From: "fromzone", To: "tozone", Expect: tt.expect}},
			}
			mock := &backends.MockBackend{
				PingResult: &system.PingResult{Reachable: tt.reachable},
			}
			eng := NewEngine(spec)
			eng.Backend = mock
			// runnerCtx.Networks empty → runner not in from zone
			result, err := eng.runIsolation(context.Background(), spec.Assertions[0])
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Status != models.StatusWarn {
				t.Errorf("expected warn from outside the source zone, got %s: %s", result.Status, result.Summary)
			}
			if !strings.Contains(result.Summary, tt.wantSummary) {
				t.Errorf("summary %q does not contain %q", result.Summary, tt.wantSummary)
			}
		})
	}
}

// TestRunIsolation_DefinitiveInZone verifies that hard verdicts are emitted
// when the runner is inside the source zone.
func TestRunIsolation_DefinitiveInZone(t *testing.T) {
	tests := []struct {
		name      string
		expect    string
		reachable bool
		want      models.Status
	}{
		{name: "deny blocked", expect: "deny", reachable: false, want: models.StatusPass},
		{name: "deny reachable", expect: "deny", reachable: true, want: models.StatusFail},
		{name: "allow reachable", expect: "allow", reachable: true, want: models.StatusPass},
		{name: "allow blocked", expect: "allow", reachable: false, want: models.StatusFail},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := &intent.Spec{
				Version: 1, Site: "test",
				Networks: []intent.Network{
					{Name: "fromnet", CIDR: "10.0.0.0/24", Gateway: "10.0.0.1", Zone: "fromzone"},
					{Name: "tonet", CIDR: "10.0.1.0/24", Gateway: "10.0.1.1", Zone: "tozone"},
				},
				Assertions: []intent.Assertion{{Type: "isolation", From: "fromzone", To: "tozone", Expect: tt.expect}},
			}
			mock := &backends.MockBackend{
				PingResult: &system.PingResult{Reachable: tt.reachable},
			}
			eng := NewEngine(spec)
			eng.Backend = mock
			eng.runnerCtx = models.RunnerContext{Networks: []string{"fromnet"}}
			result, err := eng.runIsolation(context.Background(), spec.Assertions[0])
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Status != tt.want {
				t.Errorf("expected %s, got %s: %s", tt.want, result.Status, result.Summary)
			}
		})
	}
}

func TestRunIsolation_TargetNotFound(t *testing.T) {
	spec := &intent.Spec{Version: 1, Site: "test", Networks: []intent.Network{{Name: "lan", CIDR: "10.0.0.0/24"}}}
	a := intent.Assertion{Type: "isolation", From: "zone1", To: "nonexistent-zone", Expect: "deny"}
	eng := NewEngine(spec)
	eng.Backend = &backends.MockBackend{}
	result, err := eng.runIsolation(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusError {
		t.Errorf("expected error for unresolved target, got %s", result.Status)
	}
}

func TestRunIsolation_NoGateway(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Networks: []intent.Network{
			{Name: "fromnet", CIDR: "10.0.0.0/24", Zone: "fromzone"},
			{Name: "tonet", CIDR: "10.0.1.0/24", Zone: "tozone"}, // no gateway
		},
		Assertions: []intent.Assertion{{Type: "isolation", From: "fromzone", To: "tozone", Expect: "deny"}},
	}
	mock := &backends.MockBackend{}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runIsolation(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// No gateway means no tests could be run → warn
	if result.Status != models.StatusWarn {
		t.Errorf("expected warn when no gateway, got %s: %s", result.Status, result.Summary)
	}
}

// --- runVPNRoute ---

func TestRunVPNRoute_ViaTunnel(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		VPN:        []intent.VPNConfig{{Name: "work", Type: "wireguard", Interface: "wg0"}},
		Assertions: []intent.Assertion{{Type: "vpn_route", VPN: "work", Target: "10.0.0.1", ExpectTunnel: ptrBool(true)}},
	}
	mock := &backends.MockBackend{
		RouteResult: &system.Route{Device: "wg0", Gateway: "10.0.0.1", Destination: "10.0.0.0/8"},
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runVPNRoute(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass for tunnel route, got %s: %s", result.Status, result.Summary)
	}
}

func TestRunVPNRoute_NotViaTunnel(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		VPN:        []intent.VPNConfig{{Name: "work", Type: "wireguard", Interface: "wg0"}},
		Assertions: []intent.Assertion{{Type: "vpn_route", VPN: "work", Target: "10.0.0.1", ExpectTunnel: ptrBool(true)}},
	}
	mock := &backends.MockBackend{
		RouteResult:        &system.Route{Device: "eth0", Gateway: "192.168.1.1", Destination: "10.0.0.0/8"},
		VPNInterfaceResult: false,
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runVPNRoute(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusFail {
		t.Errorf("expected fail for non-tunnel route, got %s: %s", result.Status, result.Summary)
	}
}

func TestRunVPNRoute_VPNNotFound(t *testing.T) {
	spec := &intent.Spec{Version: 1, Site: "test"}
	a := intent.Assertion{Type: "vpn_route", VPN: "missing", Target: "10.0.0.1"}
	eng := NewEngine(spec)
	_, err := eng.runVPNRoute(context.Background(), a)
	if err == nil {
		t.Fatal("expected error for missing VPN")
	}
}

func TestRunVPNRoute_ExpectTunnelFalse_DirectRoutePasses(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		VPN:        []intent.VPNConfig{{Name: "work", Type: "wireguard", Interface: "wg0"}},
		Assertions: []intent.Assertion{{Type: "vpn_route", VPN: "work", Target: "10.0.0.1", ExpectTunnel: ptrBool(false)}},
	}
	mock := &backends.MockBackend{
		RouteResult:        &system.Route{Device: "eth0", Gateway: "192.168.1.1", Destination: "10.0.0.0/8"},
		VPNInterfaceResult: false,
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runVPNRoute(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass for direct route with expect_tunnel false, got %s: %s", result.Status, result.Summary)
	}
}

func TestRunVPNRoute_ExpectTunnelFalse_TunnelRouteFails(t *testing.T) {
	// Regression: expect_tunnel: false used to fall into the always-pass
	// else branch, so a route leaking through the tunnel passed a
	// split-tunnel expectation.
	spec := &intent.Spec{
		Version: 1, Site: "test",
		VPN:        []intent.VPNConfig{{Name: "work", Type: "wireguard", Interface: "wg0"}},
		Assertions: []intent.Assertion{{Type: "vpn_route", VPN: "work", Target: "10.0.0.1", ExpectTunnel: ptrBool(false)}},
	}
	mock := &backends.MockBackend{
		RouteResult:        &system.Route{Device: "wg0", Gateway: "10.0.0.1", Destination: "10.0.0.0/8"},
		VPNInterfaceResult: false,
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runVPNRoute(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusFail {
		t.Errorf("expected fail for tunnel route with expect_tunnel false, got %s: %s", result.Status, result.Summary)
	}
	if len(result.Violations) == 0 {
		t.Error("expected a violation naming the tunnel device")
	}
}

func TestRunVPNRoute_NoExpectationInformational(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		VPN:        []intent.VPNConfig{{Name: "work", Type: "wireguard", Interface: "wg0"}},
		Assertions: []intent.Assertion{{Type: "vpn_route", VPN: "work", Target: "10.0.0.1"}},
	}
	mock := &backends.MockBackend{
		RouteResult:        &system.Route{Device: "wg0", Gateway: "10.0.0.1", Destination: "10.0.0.0/8"},
		VPNInterfaceResult: false,
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runVPNRoute(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass for informational route check, got %s: %s", result.Status, result.Summary)
	}
}

// --- runRouteCheck ---

func TestRunRouteCheck(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "route_check", Target: "8.8.8.8"}},
	}
	mock := &backends.MockBackend{
		RouteResult: &system.Route{Device: "eth0", Gateway: "192.168.1.1", Destination: "0.0.0.0/0"},
	}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runRouteCheck(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass, got %s", result.Status)
	}
	if result.Observed["gateway"] != "192.168.1.1" {
		t.Errorf("expected gateway 192.168.1.1, got %v", result.Observed["gateway"])
	}
}

func TestRunRouteCheck_RouteError(t *testing.T) {
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Assertions: []intent.Assertion{{Type: "route_check", Target: "8.8.8.8"}},
	}
	mock := &backends.MockBackend{RouteErr: backends.BackendError("route lookup failed")}
	eng := NewEngine(spec)
	eng.Backend = mock
	result, err := eng.runRouteCheck(context.Background(), spec.Assertions[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusError {
		t.Errorf("expected error status, got %s", result.Status)
	}
}
