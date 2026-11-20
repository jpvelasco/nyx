package audit

import (
	"errors"
	"net"
	"testing"
)

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
