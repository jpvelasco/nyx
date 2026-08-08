//go:build windows

package system

import (
	"context"
	"testing"
)

func TestParseRoutePrint(t *testing.T) {
	output := `===========================================================================
Interface List
  1...00 11 22 33 44 55 ......Realtek PCIe GbE Family Controller
===========================================================================

IPv4 Route Table
===========================================================================
Active Routes:
Network Destination        Netmask          Gateway       Interface  Metric
          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.50     35
        127.0.0.0        255.0.0.0         On-link        127.0.0.1    331
        127.0.0.1  255.255.255.255         On-link        127.0.0.1    331
      192.168.1.0    255.255.255.0         On-link     192.168.1.50    291
  192.168.1.255  255.255.255.255         On-link     192.168.1.50    291
Persistent Routes:
  None
===========================================================================
`
	routes := parseRoutePrint(output)
	if len(routes) != 5 {
		t.Fatalf("expected 5 routes, got %d: %+v", len(routes), routes)
	}

	// Default route rewritten to "default".
	if routes[0].Destination != "default" {
		t.Errorf("expected default route, got %q", routes[0].Destination)
	}
	if routes[0].Gateway != "192.168.1.1" {
		t.Errorf("expected gateway 192.168.1.1, got %q", routes[0].Gateway)
	}
	if routes[0].Device != "192.168.1.50" {
		t.Errorf("expected device 192.168.1.50, got %q", routes[0].Device)
	}
	if routes[0].Metric != 35 {
		t.Errorf("expected metric 35, got %d", routes[0].Metric)
	}

	// Host routes keep a /32 prefix.
	if routes[2].Destination != "127.0.0.1/32" {
		t.Errorf("expected 127.0.0.1/32, got %q", routes[2].Destination)
	}

	// Network routes gain their prefix length.
	if routes[3].Destination != "192.168.1.0/24" {
		t.Errorf("expected 192.168.1.0/24, got %q", routes[3].Destination)
	}
}

func TestParseRoutePrintEdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   int
	}{
		{"empty", "", 0},
		{"only headers", "Active Routes:\nNetwork Destination   Netmask   Gateway   Interface  Metric\n", 0},
		{"before active routes", "Interface List\n1...iface\n\nActive Routes:\n", 0},
		{"short fields skipped", "Active Routes:\n0.0.0.0 0.0.0.0 192.168.1.1\n", 0},
		{"bad metric ignored", "Active Routes:\n10.0.0.0 255.255.255.0 On-link 10.0.0.1 not-a-number\n", 1},
		{"invalid mask no prefix", "Active Routes:\n10.0.0.0 not-a-mask On-link 10.0.0.1 5\n", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseRoutePrint(tt.output)
			if len(got) != tt.want {
				t.Fatalf("parseRoutePrint = %d routes, want %d (got %+v)", len(got), tt.want, got)
			}
		})
	}
}

func TestNetmaskToPrefix(t *testing.T) {
	tests := []struct {
		mask string
		want int
	}{
		{"255.255.255.0", 24},
		{"255.255.0.0", 16},
		{"255.0.0.0", 8},
		{"0.0.0.0", 0},
		{"not-a-mask", 0},
		{"", 0},
		{"ffff:ffff::", 0}, // IPv6 mask is not a valid IPv4 netmask
	}
	for _, tt := range tests {
		if got := netmaskToPrefix(tt.mask); got != tt.want {
			t.Errorf("netmaskToPrefix(%q) = %d, want %d", tt.mask, got, tt.want)
		}
	}
}

func TestGetRoutes(t *testing.T) {
	routes, err := GetRoutes(context.Background())
	if err != nil {
		t.Fatalf("GetRoutes error: %v", err)
	}
	if len(routes) == 0 {
		t.Fatal("expected at least one route on a Windows host")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := GetRoutes(ctx); err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestGetRouteToTarget(t *testing.T) {
	ctx := context.Background()

	t.Run("loopback", func(t *testing.T) {
		route, err := GetRouteToTarget(ctx, "127.0.0.1")
		if err != nil {
			t.Fatalf("GetRouteToTarget error: %v", err)
		}
		if route == nil || route.Destination != "127.0.0.1" {
			t.Fatalf("unexpected route: %+v", route)
		}
		if route.Device == "" {
			t.Fatal("expected a device on the loopback route")
		}
	})

	t.Run("invalid target", func(t *testing.T) {
		if _, err := GetRouteToTarget(ctx, "not-an-ip"); err == nil {
			t.Fatal("expected error for invalid target")
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		cctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := GetRouteToTarget(cctx, "127.0.0.1"); err == nil {
			t.Fatal("expected error for cancelled context")
		}
	})
}

func TestPing(t *testing.T) {
	lookup(t, "ping")

	t.Run("loopback reachable", func(t *testing.T) {
		pr, err := Ping(context.Background(), "127.0.0.1")
		if err != nil {
			t.Fatalf("Ping error: %v", err)
		}
		if !pr.Reachable {
			t.Errorf("expected loopback reachable, got %+v", pr)
		}
		if pr.PacketLoss >= 100 {
			t.Errorf("expected packet loss < 100, got %+v", pr)
		}
	})

	t.Run("unreachable hostname", func(t *testing.T) {
		// 256.256.256.256 fails host lookup locally — no network egress.
		pr, err := Ping(context.Background(), "256.256.256.256")
		if err != nil {
			t.Fatalf("Ping error: %v", err)
		}
		if pr.Reachable {
			t.Errorf("expected unreachable result, got %+v", pr)
		}
		if pr.PacketLoss != 100 {
			t.Errorf("expected 100%% loss, got %+v", pr)
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := Ping(ctx, "127.0.0.1"); err == nil {
			t.Fatal("expected error for cancelled context")
		}
	})
}

func TestTraceroute(t *testing.T) {
	lookup(t, "tracert")

	t.Run("loopback", func(t *testing.T) {
		hops, err := Traceroute(context.Background(), "127.0.0.1")
		if err != nil {
			t.Fatalf("Traceroute error: %v", err)
		}
		if len(hops) == 0 {
			t.Fatal("expected at least one hop to loopback")
		}
		if hops[0].Address == "" {
			t.Errorf("expected hop address, got %+v", hops[0])
		}
	})

	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := Traceroute(ctx, "127.0.0.1"); err == nil {
			t.Fatal("expected error for cancelled context")
		}
	})
}

func TestParseTracertLine(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantNum  int
		wantAddr string
		wantRTT  string
		wantNil  bool
	}{
		{"full hop", "  1     1 ms     1 ms     1 ms  127.0.0.1", 1, "127.0.0.1", "1 ms", false},
		{"sub-ms rtt", "  1    <1 ms    <1 ms    <1 ms  127.0.0.1", 1, "127.0.0.1", "<1 ms", false},
		{"star rtt skipped", "  1     *        1 ms     1 ms   127.0.0.1", 1, "127.0.0.1", "1 ms", false},
		{"timeout hop", "  2     *        *        *     Request timed out.", 2, "*", "", false},
		{"star address", "  3     *        *        *     out.", 3, "*", "", false},
		{"too short", "1", 0, "", "", true},
		{"non-numeric hop", "abc 127.0.0.1", 0, "", "", true},
		{"non-ip last field", "  4     1 ms     1 ms     1 ms  gateway.home", 4, "*", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hop := parseTracertLine(tt.line)
			if tt.wantNil {
				if hop != nil {
					t.Fatalf("expected nil hop, got %+v", hop)
				}
				return
			}
			if hop == nil {
				t.Fatal("expected hop")
			}
			if hop.Number != tt.wantNum || hop.Address != tt.wantAddr || hop.RTT != tt.wantRTT {
				t.Fatalf("got %+v, want num=%d addr=%q rtt=%q", hop, tt.wantNum, tt.wantAddr, tt.wantRTT)
			}
		})
	}
}

func TestGetInterfaces(t *testing.T) {
	ifaces, err := GetInterfaces(context.Background())
	if err != nil {
		t.Fatalf("GetInterfaces error: %v", err)
	}
	if len(ifaces) == 0 {
		t.Fatal("expected at least one interface")
	}
	for _, iface := range ifaces {
		if iface.Name == "" {
			t.Errorf("expected interface name, got %+v", iface)
		}
		if iface.State != "up" && iface.State != "down" {
			t.Errorf("expected up/down state, got %+v", iface)
		}
	}
}

func TestCheckVPNInterface(t *testing.T) {
	ctx := context.Background()

	t.Run("non-vpn name", func(t *testing.T) {
		vpn, err := CheckVPNInterface(ctx, "Ethernet")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if vpn {
			t.Error("expected non-VPN name to report false")
		}
	})

	t.Run("vpn name not present", func(t *testing.T) {
		vpn, err := CheckVPNInterface(ctx, "wg-nyx-test")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if vpn {
			t.Error("expected absent VPN interface to report false")
		}
	})

	t.Run("present vpn interface", func(t *testing.T) {
		ifaces, err := GetInterfaces(ctx)
		if err != nil {
			t.Fatalf("GetInterfaces error: %v", err)
		}
		var vpnName string
		for _, iface := range ifaces {
			if isVPNInterfaceName(iface.Name) {
				vpnName = iface.Name
				break
			}
		}
		if vpnName == "" {
			t.Skip("no VPN-named interface present on this host")
		}
		vpn, err := CheckVPNInterface(ctx, vpnName)
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", vpnName, err)
		}
		_ = vpn // value depends on interface state; no error is the contract
	})
}
