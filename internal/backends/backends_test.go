package backends

import (
	"context"
	"os/exec"
	"testing"

	"github.com/jpvelasco/nyx/internal/backends/dns"
	"github.com/jpvelasco/nyx/internal/backends/health"
	"github.com/jpvelasco/nyx/internal/backends/nmap"
	"github.com/jpvelasco/nyx/internal/backends/system"
	"github.com/jpvelasco/nyx/internal/models"
)

func TestNewDefaultBackendImplementsBackend(t *testing.T) {
	var _ Backend = (*defaultBackend)(nil)
	b := NewDefaultBackend()
	if _, ok := b.(*defaultBackend); !ok {
		t.Fatalf("NewDefaultBackend returned %T, want *defaultBackend", b)
	}
}

func pingAvailable() bool {
	_, err := exec.LookPath("ping")
	return err == nil
}

func TestDefaultBackendDiscoverInvalidCIDR(t *testing.T) {
	ctx := context.Background()
	b := NewDefaultBackend()

	// Invalid CIDR fails before nmap is consulted, so this is safe to run
	// even when nmap is installed.
	_, err := b.Discover(ctx, "not-a-cidr", nmap.DefaultScanOptions)
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestDefaultBackendPortScan(t *testing.T) {
	if nmap.Available() {
		t.Skip("nmap installed; would run a real scan")
	}
	ctx := context.Background()
	b := NewDefaultBackend()

	result, err := b.PortScan(ctx, "192.0.2.1", []int{22}, "tcp", nmap.DefaultScanOptions)
	if err == nil {
		t.Fatal("expected error when nmap is missing")
	}
	if result == nil || result.Status != models.StatusError {
		t.Fatalf("expected StatusError result, got %+v", result)
	}
}

func TestDefaultBackendPing(t *testing.T) {
	if !pingAvailable() {
		t.Skip("ping binary not available")
	}
	ctx := context.Background()
	b := NewDefaultBackend()

	result, err := b.Ping(ctx, "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected ping error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil PingResult")
	}
}

func TestDefaultBackendGetRouteToTarget(t *testing.T) {
	ctx := context.Background()
	b := NewDefaultBackend()

	route, err := b.GetRouteToTarget(ctx, "127.0.0.1")
	if err != nil {
		// Route table lookups are local; any error here is environmental.
		t.Fatalf("unexpected route lookup error: %v", err)
	}
	if route == nil || route.Device == "" {
		t.Fatalf("expected a route with a device, got %+v", route)
	}
}

func TestDefaultBackendGetInterfaces(t *testing.T) {
	ctx := context.Background()
	b := NewDefaultBackend()

	ifaces, err := b.GetInterfaces(ctx)
	if err != nil {
		t.Fatalf("unexpected interfaces error: %v", err)
	}
	if len(ifaces) == 0 {
		t.Fatal("expected at least one interface")
	}
}

func TestDefaultBackendCheckVPNInterface(t *testing.T) {
	ctx := context.Background()
	b := NewDefaultBackend()

	// wg0 is a VPN-style name that should not exist as a local interface.
	vpn, err := b.CheckVPNInterface(ctx, "wg0")
	if err != nil {
		t.Fatalf("unexpected VPN interface error: %v", err)
	}
	if vpn {
		t.Fatal("expected wg0 to not be an active local interface")
	}
}

func TestDefaultBackendResolve(t *testing.T) {
	ctx := context.Background()
	b := NewDefaultBackend()

	// Pointing at localhost:53 fails fast with a connection error instead of
	// using the real network.
	result, err := b.Resolve(ctx, "example.com", "127.0.0.1")
	if err != nil {
		t.Fatalf("Resolve must not surface transport errors, got %v", err)
	}
	if result == nil || result.Status != models.StatusError {
		t.Fatalf("expected StatusError result, got %+v", result)
	}
}

func TestDefaultBackendResolveExpect(t *testing.T) {
	ctx := context.Background()
	b := NewDefaultBackend()

	result, err := b.ResolveExpect(ctx, "example.com", "127.0.0.1", "192.0.2.1")
	if err != nil {
		t.Fatalf("ResolveExpect must not surface transport errors, got %v", err)
	}
	if result == nil || result.Status != models.StatusError {
		t.Fatalf("expected StatusError result, got %+v", result)
	}
}

func TestDefaultBackendCheckDNSSEC(t *testing.T) {
	if dns.Available() {
		t.Skip("dig installed; would query a real resolver")
	}
	ctx := context.Background()
	b := NewDefaultBackend()

	result, err := b.CheckDNSSEC(ctx, "example.com", "")
	if err != nil {
		t.Fatalf("unexpected DNSSEC error: %v", err)
	}
	if result == nil || result.Status != models.StatusError {
		t.Fatalf("expected StatusError result, got %+v", result)
	}
}

func TestDefaultBackendDigAvailable(t *testing.T) {
	b := NewDefaultBackend()
	got := b.DigAvailable()
	if got != dns.Available() {
		t.Fatalf("DigAvailable() = %v, want %v", got, dns.Available())
	}
}

func TestDefaultBackendPingCheck(t *testing.T) {
	if !pingAvailable() {
		t.Skip("ping binary not available")
	}
	ctx := context.Background()
	b := NewDefaultBackend()

	result, stats, err := b.PingCheck(ctx, "127.0.0.1", 1)
	if err != nil {
		t.Fatalf("unexpected ping check error: %v", err)
	}
	if result == nil || result.Status != models.StatusPass {
		t.Fatalf("expected StatusPass result, got %+v", result)
	}
	if stats == nil || stats.Target != "127.0.0.1" {
		t.Fatalf("unexpected stats: %+v", stats)
	}
}

func TestDefaultBackendCheckLatencyAndLoss(t *testing.T) {
	if !pingAvailable() {
		t.Skip("ping binary not available")
	}
	ctx := context.Background()
	b := NewDefaultBackend()

	// Zero thresholds mean no violations are possible.
	result, err := b.CheckLatencyAndLoss(ctx, "127.0.0.1", 0, 0)
	if err != nil {
		t.Fatalf("unexpected latency check error: %v", err)
	}
	if result == nil || result.Status != models.StatusPass {
		t.Fatalf("expected StatusPass result, got %+v", result)
	}
}

func TestDefaultBackendProbeMTU(t *testing.T) {
	if !pingAvailable() {
		t.Skip("ping binary not available")
	}
	ctx := context.Background()
	b := NewDefaultBackend()

	// Loopback supports the full MTU range, so 1500 should be discovered.
	result, err := b.ProbeMTU(ctx, "127.0.0.1", 1500)
	if err != nil {
		t.Fatalf("unexpected MTU probe error: %v", err)
	}
	if result == nil || result.Status != models.StatusPass {
		t.Fatalf("expected StatusPass result, got %+v", result)
	}
}

func TestDefaultBackendNewOmadaClient(t *testing.T) {
	ctx := context.Background()
	b := NewDefaultBackend()

	// Port 1 on localhost is never listening; the info fetch fails fast.
	client, err := b.NewOmadaClient(ctx, "127.0.0.1:1", true, "")
	if err == nil {
		t.Fatal("expected error connecting to a closed local port")
	}
	if client != nil {
		t.Fatalf("expected nil client on error, got %+v", client)
	}
}

// --- MockBackend ---

func TestMockBackendDiscover(t *testing.T) {
	ctx := context.Background()
	res := models.NewCheckResult("nmap", "subnet_discovery", "nmap", "10.0.0.0/24")

	t.Run("preconfigured result", func(t *testing.T) {
		m := &MockBackend{DiscoverResult: res}
		got, err := m.Discover(ctx, "10.0.0.0/24", nmap.DefaultScanOptions)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != res {
			t.Fatal("expected preconfigured result")
		}
	})

	t.Run("result func branch", func(t *testing.T) {
		m := &MockBackend{DiscoverResultFunc: func(cidr string) *models.CheckResult {
			return models.NewCheckResult("nmap", "subnet_discovery", "nmap", cidr)
		}}
		got, err := m.Discover(ctx, "10.0.0.0/24", nmap.DefaultScanOptions)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == nil || got.Target != "10.0.0.0/24" {
			t.Fatalf("expected result for cidr, got %+v", got)
		}
	})

	t.Run("error", func(t *testing.T) {
		m := &MockBackend{DiscoverErr: BackendError("boom")}
		if _, err := m.Discover(ctx, "10.0.0.0/24", nmap.DefaultScanOptions); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestMockBackendPortScan(t *testing.T) {
	ctx := context.Background()
	res := models.NewCheckResult("nmap", "port_check", "nmap", "10.0.0.1")

	t.Run("result", func(t *testing.T) {
		m := &MockBackend{PortScanResult: res}
		got, err := m.PortScan(ctx, "10.0.0.1", []int{22}, "tcp", nmap.DefaultScanOptions)
		if err != nil || got != res {
			t.Fatalf("got %+v, err %v", got, err)
		}
	})

	t.Run("error", func(t *testing.T) {
		m := &MockBackend{PortScanErr: BackendError("boom")}
		if _, err := m.PortScan(ctx, "10.0.0.1", []int{22}, "tcp", nmap.DefaultScanOptions); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestMockBackendSystemMethods(t *testing.T) {
	ctx := context.Background()

	t.Run("Ping", func(t *testing.T) {
		pr := &system.PingResult{Reachable: true}
		m := &MockBackend{PingResult: pr}
		got, err := m.Ping(ctx, "10.0.0.1")
		if err != nil || got != pr {
			t.Fatalf("got %+v, err %v", got, err)
		}
		m = &MockBackend{PingErr: BackendError("boom")}
		if _, err := m.Ping(ctx, "10.0.0.1"); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("GetRouteToTarget", func(t *testing.T) {
		r := &system.Route{Destination: "10.0.0.0/24"}
		m := &MockBackend{RouteResult: r}
		got, err := m.GetRouteToTarget(ctx, "10.0.0.1")
		if err != nil || got != r {
			t.Fatalf("got %+v, err %v", got, err)
		}
		m = &MockBackend{RouteErr: BackendError("boom")}
		if _, err := m.GetRouteToTarget(ctx, "10.0.0.1"); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("GetInterfaces", func(t *testing.T) {
		ifaces := []system.Interface{{Name: "eth0", State: "up"}}
		m := &MockBackend{InterfacesResult: ifaces}
		got, err := m.GetInterfaces(ctx)
		if err != nil || len(got) != 1 || got[0].Name != "eth0" {
			t.Fatalf("got %+v, err %v", got, err)
		}
		m = &MockBackend{InterfacesErr: BackendError("boom")}
		if _, err := m.GetInterfaces(ctx); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("CheckVPNInterface", func(t *testing.T) {
		m := &MockBackend{VPNInterfaceResult: true}
		got, err := m.CheckVPNInterface(ctx, "wg0")
		if err != nil || !got {
			t.Fatalf("got %v, err %v", got, err)
		}
		m = &MockBackend{VPNInterfaceErr: BackendError("boom")}
		if _, err := m.CheckVPNInterface(ctx, "wg0"); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestMockBackendDNSMethods(t *testing.T) {
	ctx := context.Background()

	t.Run("Resolve", func(t *testing.T) {
		res := models.NewCheckResult("dns", "dns_check", "dns", "example.com")
		m := &MockBackend{ResolveResult: res}
		got, err := m.Resolve(ctx, "example.com", "")
		if err != nil || got != res {
			t.Fatalf("got %+v, err %v", got, err)
		}
		m = &MockBackend{ResolveErr: BackendError("boom")}
		if _, err := m.Resolve(ctx, "example.com", ""); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("ResolveExpect", func(t *testing.T) {
		res := models.NewCheckResult("dns", "dns_check", "dns", "example.com")
		m := &MockBackend{ResolveExpectResult: res}
		got, err := m.ResolveExpect(ctx, "example.com", "", "192.0.2.1")
		if err != nil || got != res {
			t.Fatalf("got %+v, err %v", got, err)
		}
		m = &MockBackend{ResolveExpectErr: BackendError("boom")}
		if _, err := m.ResolveExpect(ctx, "example.com", "", "192.0.2.1"); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("CheckDNSSEC", func(t *testing.T) {
		res := models.NewCheckResult("dig", "dns_check", "dns", "example.com")
		m := &MockBackend{DNSSECResult: res}
		got, err := m.CheckDNSSEC(ctx, "example.com", "")
		if err != nil || got != res {
			t.Fatalf("got %+v, err %v", got, err)
		}
		m = &MockBackend{DNSSECErr: BackendError("boom")}
		if _, err := m.CheckDNSSEC(ctx, "example.com", ""); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("DigAvailable", func(t *testing.T) {
		m := &MockBackend{DigAvailableResult: true}
		if !m.DigAvailable() {
			t.Fatal("expected true")
		}
	})
}

func TestMockBackendHealthMethods(t *testing.T) {
	ctx := context.Background()

	t.Run("PingCheck", func(t *testing.T) {
		res := models.NewCheckResult("ping", "network_health", "system", "10.0.0.1")
		stats := &health.PingStats{}
		m := &MockBackend{PingCheckResult: res, PingCheckStats: stats}
		got, gotStats, err := m.PingCheck(ctx, "10.0.0.1", 1)
		if err != nil || got != res || gotStats != stats {
			t.Fatalf("got %+v, stats %+v, err %v", got, gotStats, err)
		}
		m = &MockBackend{PingCheckErr: BackendError("boom")}
		if _, _, err := m.PingCheck(ctx, "10.0.0.1", 1); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("CheckLatencyAndLoss", func(t *testing.T) {
		res := models.NewCheckResult("ping", "network_health", "system", "10.0.0.1")
		m := &MockBackend{LatencyResult: res}
		got, err := m.CheckLatencyAndLoss(ctx, "10.0.0.1", 100, 5)
		if err != nil || got != res {
			t.Fatalf("got %+v, err %v", got, err)
		}
		m = &MockBackend{LatencyErr: BackendError("boom")}
		if _, err := m.CheckLatencyAndLoss(ctx, "10.0.0.1", 100, 5); err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("ProbeMTU", func(t *testing.T) {
		res := models.NewCheckResult("ping", "network_health", "system", "10.0.0.1")
		m := &MockBackend{MTUResult: res}
		got, err := m.ProbeMTU(ctx, "10.0.0.1", 1500)
		if err != nil || got != res {
			t.Fatalf("got %+v, err %v", got, err)
		}
		m = &MockBackend{MTUErr: BackendError("boom")}
		if _, err := m.ProbeMTU(ctx, "10.0.0.1", 1500); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestMockBackendNewOmadaClient(t *testing.T) {
	ctx := context.Background()
	m := &MockBackend{OmadaErr: BackendError("boom")}
	if _, err := m.NewOmadaClient(ctx, "10.0.0.1", false, ""); err == nil {
		t.Fatal("expected error")
	}
}

func TestBackendError(t *testing.T) {
	var err error = BackendError("test message")
	if err.Error() != "test message" {
		t.Fatalf("unexpected message: %q", err.Error())
	}
}
