//go:build linux

package system

import (
	"context"
	"testing"
)

func TestParseIPRouteLine(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		want    Route
		wantNil bool
	}{
		{
			"full route",
			"default via 192.168.1.1 dev eth0 proto dhcp metric 100",
			Route{Destination: "default", Gateway: "192.168.1.1", Device: "eth0", Protocol: "dhcp", Metric: 100},
			false,
		},
		{
			"connected route",
			"10.0.0.0/24 dev wg0 proto kernel scope link",
			Route{Destination: "10.0.0.0/24", Device: "wg0", Protocol: "kernel", Scope: "link"},
			false,
		},
		{
			"bad metric kept as zero",
			"10.0.0.0/24 dev eth0 metric abc",
			Route{Destination: "10.0.0.0/24", Device: "eth0"},
			false,
		},
		{"empty line", "   ", Route{}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseIPRouteLine(tt.line)
			if tt.wantNil {
				if got != nil {
					t.Fatalf("expected nil, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected route")
			}
			if *got != tt.want {
				t.Fatalf("got %+v, want %+v", *got, tt.want)
			}
		})
	}
}

func TestParseIPRouteOutput(t *testing.T) {
	output := "default via 192.168.1.1 dev eth0 proto dhcp metric 100\n" +
		"\n" +
		"   \n" +
		"10.0.0.0/24 dev wg0 proto kernel scope link\n"
	routes := parseIPRouteOutput(output)
	if len(routes) != 2 {
		t.Fatalf("expected 2 routes, got %d: %+v", len(routes), routes)
	}
	if routes[0].Destination != "default" || routes[0].Device != "eth0" {
		t.Errorf("unexpected default route: %+v", routes[0])
	}
	if routes[1].Destination != "10.0.0.0/24" || routes[1].Device != "wg0" {
		t.Errorf("unexpected connected route: %+v", routes[1])
	}
}

func TestParseInterfacesText(t *testing.T) {
	output := `garbage before first header
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: eth0@NONE: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP
    inet 192.168.1.50/24 brd 192.168.1.255 scope global eth0
    inet6 fe80::21a:2bff:fe3c:4d5e/64 scope link
3: wg0: <POINTOPOINT,NOARP> mtu 1420 qdisc noqueue state DOWN
`
	ifaces := parseInterfacesText(output)
	if len(ifaces) != 3 {
		t.Fatalf("expected 3 interfaces, got %d: %+v", len(ifaces), ifaces)
	}

	lo := ifaces[0]
	if lo.Name != "lo" || lo.State != "up" || lo.Type != "loopback" {
		t.Errorf("unexpected lo: %+v", lo)
	}
	if len(lo.Addrs) != 1 || lo.Addrs[0] != "127.0.0.1/8" {
		t.Errorf("unexpected lo addrs: %+v", lo.Addrs)
	}

	eth := ifaces[1]
	if eth.Name != "eth0" || eth.State != "up" || eth.Type != "ethernet" {
		t.Errorf("unexpected eth0: %+v", eth)
	}
	if len(eth.Addrs) != 2 || eth.Addrs[0] != "192.168.1.50/24" || eth.Addrs[1] != "fe80::21a:2bff:fe3c:4d5e/64" {
		t.Errorf("unexpected eth0 addrs: %+v", eth.Addrs)
	}

	wg := ifaces[2]
	if wg.Name != "wg0" || wg.State != "down" || wg.Type != "wireguard" {
		t.Errorf("unexpected wg0: %+v", wg)
	}
}

func TestParseInterfacesJSON(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		output := `[
  {
    "ifname": "lo",
    "operstate": "UNKNOWN",
    "link_type": "loopback",
    "addr_info": [{"family": "inet", "local": "127.0.0.1", "prefixlen": 8}]
  },
  {
    "ifname": "eth0",
    "operstate": "UP",
    "link_type": "ether",
    "addr_info": [
      {"family": "inet", "local": "192.168.1.50", "prefixlen": 24},
      {"family": "inet6", "local": "fe80::1", "prefixlen": 64}
    ]
  }
]`
		ifaces, err := parseInterfacesJSON(output)
		if err != nil {
			t.Fatalf("parseInterfacesJSON error: %v", err)
		}
		if len(ifaces) != 2 {
			t.Fatalf("expected 2 interfaces, got %d", len(ifaces))
		}
		eth := ifaces[1]
		if eth.Name != "eth0" || eth.State != "up" || eth.Type != "ethernet" {
			t.Errorf("unexpected eth0: %+v", eth)
		}
		if len(eth.Addrs) != 2 || eth.Addrs[0] != "192.168.1.50/24" || eth.Addrs[1] != "fe80::1/64" {
			t.Errorf("unexpected eth0 addrs: %+v", eth.Addrs)
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		if _, err := parseInterfacesJSON("{not json"); err == nil {
			t.Fatal("expected error for malformed JSON")
		}
	})
}

func TestLinuxGetRoutes(t *testing.T) {
	lookup(t, "ip")

	routes, err := GetRoutes(context.Background())
	if err != nil {
		t.Fatalf("GetRoutes error: %v", err)
	}
	if len(routes) == 0 {
		t.Fatal("expected at least one route on a Linux host")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := GetRoutes(ctx); err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestLinuxGetRouteToTarget(t *testing.T) {
	lookup(t, "ip")

	route, err := GetRouteToTarget(context.Background(), "127.0.0.1")
	if err != nil {
		t.Fatalf("GetRouteToTarget error: %v", err)
	}
	if route == nil || route.Device == "" {
		t.Fatalf("expected route with device, got %+v", route)
	}

	if _, err := GetRouteToTarget(context.Background(), "not-an-ip"); err == nil {
		t.Fatal("expected error for invalid target")
	}
}

func TestLinuxPing(t *testing.T) {
	lookup(t, "ping")

	t.Run("loopback reachable", func(t *testing.T) {
		pr, err := Ping(context.Background(), "127.0.0.1")
		if err != nil {
			t.Fatalf("Ping error: %v", err)
		}
		if !pr.Reachable {
			t.Errorf("expected loopback reachable, got %+v", pr)
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

func TestLinuxGetInterfaces(t *testing.T) {
	lookup(t, "ip")

	ifaces, err := GetInterfaces(context.Background())
	if err != nil {
		t.Fatalf("GetInterfaces error: %v", err)
	}
	if len(ifaces) == 0 {
		t.Fatal("expected at least one interface")
	}
}

func TestLinuxCheckVPNInterface(t *testing.T) {
	lookup(t, "ip")

	ctx := context.Background()

	t.Run("non-vpn name", func(t *testing.T) {
		vpn, err := CheckVPNInterface(ctx, "eth0")
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
}
