//go:build !windows

package system

import (
	"context"
	"testing"
)

func TestParseTracerouteLine(t *testing.T) {
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
		{"single field", "1", 0, "", "", true},
		{"no timing samples", "1 10.0.0.1", 0, "", "", true},
		{"non-numeric hop", "x  10.0.0.1  1 ms", 0, "", "", true},
		{"address with all-star samples", "3  10.0.0.1  * * *", 0, "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hop := parseTracerouteLine(tt.line)
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

func TestTraceroute(t *testing.T) {
	t.Run("loopback", func(t *testing.T) {
		hops, err := Traceroute(context.Background(), "127.0.0.1")
		if err != nil {
			t.Fatalf("Traceroute error: %v", err)
		}
		for _, hop := range hops {
			if hop.Address == "" {
				t.Errorf("expected hop address, got %+v", hop)
			}
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
