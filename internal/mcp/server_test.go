package mcp

import (
	"context"
	"testing"

	"github.com/jpvelasco/nyx/internal/backends/nmap"
)

func TestNewServer(t *testing.T) {
	server := NewServer()
	if server == nil {
		t.Error("expected non-nil server")
	}
}

func TestDispatchDiscoverSubnet(t *testing.T) {
	if !nmap.Available() {
		t.Skip("nmap not available")
	}
	ctx := context.Background()
	server := NewServer()

	_, isError := server.DispatchToolForTest(ctx, "discover_subnet", map[string]interface{}{
		"subnet":        "192.168.1.0/24",
		"scan_timing":   4,
		"scan_min_rate": 1000,
	})

	if isError {
		t.Error("unexpected error result")
	}
}
