package nmap

import (
	"context"
	"testing"
)

func TestPoliteScanOptionsDefaults(t *testing.T) {
	opts := PoliteScanOptions
	if opts.TimingTemplate != 2 {
		t.Errorf("expected TimingTemplate 2, got %d", opts.TimingTemplate)
	}
	if opts.MinRate != 50 {
		t.Errorf("expected MinRate 50, got %d", opts.MinRate)
	}
	if opts.MaxRate != 100 {
		t.Errorf("expected MaxRate 100, got %d", opts.MaxRate)
	}
}

func TestScanOptionsForMode(t *testing.T) {
	if ScanOptionsForMode("polite") != PoliteScanOptions {
		t.Error("polite should return PoliteScanOptions")
	}
	if ScanOptionsForMode("normal") != DefaultScanOptions {
		t.Error("normal should return DefaultScanOptions")
	}
	if ScanOptionsForMode("unknown") != PoliteScanOptions {
		t.Error("unknown mode should default to polite")
	}
	aggressive := ScanOptionsForMode("aggressive")
	if aggressive.TimingTemplate != 5 {
		t.Errorf("aggressive should be T5, got T%d", aggressive.TimingTemplate)
	}
}

func TestPortScanResultShape(t *testing.T) {
	if !Available() {
		t.Skip("nmap not available")
	}
	// Uses an RFC5737 non-routable address to get a quick "filtered" result
	// without actually scanning anything live. Just verifies result shape.
	result, err := PortScan(context.Background(), "192.0.2.1", []int{80, 443}, "tcp", PoliteScanOptions)
	if err != nil {
		t.Fatalf("PortScan returned error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.CheckType != "port_check" {
		t.Errorf("expected check_type 'port_check', got %q", result.CheckType)
	}
}
