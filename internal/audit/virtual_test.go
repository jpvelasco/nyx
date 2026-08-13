package audit

import (
	"errors"
	"net"
	"testing"
)

func TestVirtualNetworksFrom(t *testing.T) {
	tests := []struct {
		name  string
		addrs []net.IPNet
		want  []string
	}{
		{name: "empty", want: nil},
		{
			name:  "ipv4 masked to /24",
			addrs: []net.IPNet{{IP: net.ParseIP("10.255.144.7"), Mask: net.CIDRMask(20, 32)}},
			want:  []string{"10.255.144.0/24"},
		},
		{
			name:  "ipv6 skipped",
			addrs: []net.IPNet{{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)}},
			want:  nil,
		},
		{
			name: "mixed",
			addrs: []net.IPNet{
				{IP: net.ParseIP("10.255.174.1"), Mask: net.CIDRMask(24, 32)},
				{IP: net.ParseIP("fe80::1"), Mask: net.CIDRMask(64, 128)},
				{IP: net.ParseIP("10.255.16.1"), Mask: net.CIDRMask(20, 32)},
			},
			want: []string{"10.255.174.0/24", "10.255.16.0/24"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := virtualNetworksFrom(tt.addrs)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("got %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestVirtualIfaceNetworksShape(t *testing.T) {
	for _, cidr := range VirtualIfaceNetworks() {
		ip, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			t.Fatalf("VirtualIfaceNetworks returned invalid CIDR %q: %v", cidr, err)
		}
		if !ipNet.IP.Equal(ip) {
			t.Errorf("network %q does not contain its own network address", cidr)
		}
	}
}

func TestVirtualIfaceAddrsFromError(t *testing.T) {
	if got := virtualIfaceAddrsFrom(func() ([]net.Interface, error) {
		return nil, errors.New("boom")
	}); got != nil {
		t.Fatalf("expected nil on interface enumeration error, got %v", got)
	}
}

func TestAnyAddrIn(t *testing.T) {
	_, net24, _ := net.ParseCIDR("10.255.144.0/24")
	_, net20, _ := net.ParseCIDR("10.255.144.0/20")
	_, other, _ := net.ParseCIDR("10.0.0.0/24")
	addrs := []net.IPNet{
		{IP: net.ParseIP("10.255.144.7"), Mask: net.CIDRMask(20, 32)},
	}
	tests := []struct {
		name string
		net  *net.IPNet
		want bool
	}{
		{name: "address inside smaller network", net: net24, want: true},
		{name: "address inside own network", net: net20, want: true},
		{name: "unrelated network", net: other, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := anyAddrIn(addrs, tt.net); got != tt.want {
				t.Errorf("anyAddrIn(%v, %s) = %v, want %v", addrs, tt.net, got, tt.want)
			}
		})
	}
}
