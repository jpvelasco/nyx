//go:build darwin

package system

import "testing"

func TestParseNetstatRoutes(t *testing.T) {
	output := `Routing tables

Internet:
Destination        Gateway            Flags        Netif Expire
default            192.168.1.1        UGScg         en0
10.0.0.0/24        10.0.0.1           UGSc          utun3
127                127.0.0.1          UCS           lo0
`
	routes := parseNetstatRoutes(output)
	if len(routes) != 3 {
		t.Fatalf("expected 3 routes, got %d: %+v", len(routes), routes)
	}
	if routes[0].Destination != "default" || routes[0].Gateway != "192.168.1.1" || routes[0].Device != "en0" {
		t.Errorf("unexpected default route: %+v", routes[0])
	}
	if routes[1].Destination != "10.0.0.0/24" || routes[1].Gateway != "10.0.0.1" || routes[1].Device != "utun3" {
		t.Errorf("unexpected vpn route: %+v", routes[1])
	}
	if routes[2].Destination != "127" || routes[2].Device != "lo0" {
		t.Errorf("unexpected loopback route: %+v", routes[2])
	}
}

func TestParseNetstatRoutesEdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   int
	}{
		{"empty", "", 0},
		{"before header", "Internet:\ndefault 192.168.1.1 UGScg en0\nDestination Gateway Flags Netif\n", 0},
		{"short fields skipped", "Destination Gateway Flags Netif\ndefault 192.168.1.1 UGScg\n", 0},
		{"blank lines", "Destination Gateway Flags Netif\ndefault 192.168.1.1 UGScg en0\n\n  \n", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := len(parseNetstatRoutes(tt.output)); got != tt.want {
				t.Fatalf("parseNetstatRoutes = %d routes, want %d", got, tt.want)
			}
		})
	}
}

func TestParseTracerouteLineDarwin(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantNum  int
		wantAddr string
		wantRTT  string
		wantNil  bool
	}{
		{"full hop", "1  10.0.0.1  0.521 ms  0.456 ms  0.401 ms", 1, "10.0.0.1", "0.521 ms", false},
		{"timeout hop", "2  * * *", 2, "*", "", false},
		{"too short", "1 10.0.0.1", 0, "", "", true},
		{"non-numeric hop", "x  10.0.0.1  1 ms", 0, "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hop := parseTracerouteLineDarwin(tt.line)
			if tt.wantNil {
				if hop != nil {
					t.Fatalf("expected nil, got %+v", hop)
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

func TestParseIfconfig(t *testing.T) {
	output := `lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
	inet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	inet 192.168.1.50 netmask 0xffffff00 broadcast 192.168.1.255
	inet6 fe80::1%en0 prefixlen 64 secured scopeid 0x4
	status: active
utun3: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1400
	inet 10.0.0.2 --> 10.0.0.1 netmask 0xffffffff
bridge0: flags=8863<BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
	status: inactive
`
	ifaces := parseIfconfig(output)
	if len(ifaces) != 4 {
		t.Fatalf("expected 4 interfaces, got %d: %+v", len(ifaces), ifaces)
	}

	lo := ifaces[0]
	if lo.Name != "lo0" || lo.State != "up" || lo.Type != "loopback" {
		t.Errorf("unexpected lo0: %+v", lo)
	}
	if len(lo.Addrs) != 1 || lo.Addrs[0] != "127.0.0.1/8" {
		t.Errorf("unexpected lo0 addrs: %+v", lo.Addrs)
	}

	en := ifaces[1]
	if en.Name != "en0" || en.State != "up" || en.Type != "ethernet" {
		t.Errorf("unexpected en0: %+v", en)
	}
	if len(en.Addrs) != 2 || en.Addrs[0] != "192.168.1.50/24" || en.Addrs[1] != "fe80::1/64" {
		t.Errorf("unexpected en0 addrs: %+v", en.Addrs)
	}

	utun := ifaces[2]
	if utun.Name != "utun3" || utun.State != "up" || utun.Type != "tunnel" {
		t.Errorf("unexpected utun3: %+v", utun)
	}

	bridge := ifaces[3]
	if bridge.Name != "bridge0" || bridge.State != "down" || bridge.Type != "bridge" {
		t.Errorf("unexpected bridge0: %+v", bridge)
	}
}

func TestHexMaskToPrefix(t *testing.T) {
	tests := []struct {
		hex  string
		want int
	}{
		{"0xffffff00", 24},
		{"0xffff0000", 16},
		{"0x00000000", 0},
		{"0Xff000000", 8},
		{"not-hex", 32},
		{"", 32},
	}
	for _, tt := range tests {
		if got := hexMaskToPrefix(tt.hex); got != tt.want {
			t.Errorf("hexMaskToPrefix(%q) = %d, want %d", tt.hex, got, tt.want)
		}
	}
}
