package audit

import (
	"context"
	"net"
	"slices"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/backends"
	"github.com/jpvelasco/nyx/internal/backends/system"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
)

// --- runIsolation ---

func testRunnerInFromnet(spec *intent.Spec) runnerContext {
	return matchNetworks([]system.PingSource{{IP: net.ParseIP(spec.NetworkByName("fromnet").Gateway), Interface: "eth0"}}, spec)
}

func TestRunIsolation_Multihomed(t *testing.T) {
	spec := &intent.Spec{Networks: []intent.Network{
		{Name: "management", Zone: "management", CIDR: "10.0.11.0/24", Gateway: "10.0.11.1"},
		{Name: "iot", Zone: "devices", CIDR: "10.0.60.0/24", Gateway: "10.0.60.1"},
		{Name: "servers", CIDR: "10.0.40.0/24", Gateway: "10.0.40.1"},
	}}
	wired := system.PingSource{IP: net.ParseIP("10.0.11.20"), Interface: "ethernet"}
	wifi := system.PingSource{IP: net.ParseIP("10.0.60.15"), Interface: "wifi"}
	for _, tc := range []struct {
		name, from string
		addresses  []system.PingSource
		pingErr    error
		want       models.Status
		wantSource bool
	}{
		{"match by zone", "devices", []system.PingSource{wired, wifi}, nil, models.StatusPass, true},
		{"match by network", "iot", []system.PingSource{wired, wifi}, nil, models.StatusPass, true},
		{"selected interface", "iot", []system.PingSource{wifi}, nil, models.StatusPass, true},
		{"selected interface outside source", "iot", []system.PingSource{wired}, nil, models.StatusWarn, false},
		{"binding unavailable", "iot", []system.PingSource{wired, wifi}, backends.BackendError("bind failed"), models.StatusWarn, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eng := NewEngine(spec)
			eng.runnerCtx = matchNetworks(tc.addresses, spec)
			var gateways []string
			eng.Backend = &backends.MockBackend{PingErr: tc.pingErr, PingResultFunc: func(gateway string, source *system.PingSource) *system.PingResult {
				gateways = append(gateways, gateway)
				if (source != nil) != tc.wantSource {
					t.Fatalf("unexpected source %v", source)
				}
				if source != nil && (!source.IP.Equal(wifi.IP) || source.Interface != wifi.Interface) {
					t.Fatalf("got source %v, want %v", source, wifi)
				}
				// The default route can reach both gateways. Traffic from IoT cannot.
				return &system.PingResult{Reachable: source == nil}
			}}
			result, err := eng.runIsolation(context.Background(), intent.Assertion{From: tc.from, To: "management,servers", Expect: "deny"})
			if err != nil || result.Status != tc.want {
				t.Fatalf("got %v, %v; want %v", result, err, tc.want)
			}
			blocked, _ := result.Observed["unreachable_gateways"].([]string)
			if tc.want == models.StatusPass && (!slices.Equal(blocked, gateways) || result.Observed["source_network"] != "iot") {
				t.Errorf("observed dead paths: %v", result.Observed)
			}
			if tc.want == models.StatusWarn && len(blocked) > 0 {
				t.Errorf("unverified dead paths: %v", blocked)
			}
			if !slices.Equal(gateways, []string{"10.0.11.1", "10.0.40.1"}) {
				t.Errorf("gateways = %v", gateways)
			}
		})
	}
}

func TestRunIsolation_PartiallyMeasured(t *testing.T) {
	spec := &intent.Spec{Networks: []intent.Network{
		{Name: "iot", CIDR: "10.0.60.0/24"},
		{Name: "servers", CIDR: "10.0.40.0/24", Gateway: "10.0.40.1"},
		{Name: "media", CIDR: "10.0.50.0/24"},
	}}
	eng := NewEngine(spec)
	eng.runnerCtx = matchNetworks([]system.PingSource{{IP: net.ParseIP("10.0.60.15"), Interface: "wifi"}}, spec)
	for _, tc := range []struct {
		expect    string
		reachable bool
		want      models.Status
	}{
		{"deny", false, models.StatusWarn},
		{"deny", true, models.StatusFail},
		{"allow", false, models.StatusFail},
		{"allow", true, models.StatusWarn},
	} {
		eng.Backend = &backends.MockBackend{PingResult: &system.PingResult{Reachable: tc.reachable}}
		result, err := eng.runIsolation(t.Context(), intent.Assertion{From: "iot", To: "servers,media", Expect: tc.expect})
		if err != nil || result.Status != tc.want {
			t.Errorf("expect %s, reachable %t: got %v, %v; want %v", tc.expect, tc.reachable, result, err, tc.want)
		}
	}
}

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
	eng.runnerCtx = testRunnerInFromnet(spec)
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
	eng.runnerCtx = testRunnerInFromnet(spec)
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
			eng.runnerCtx = testRunnerInFromnet(spec)
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
