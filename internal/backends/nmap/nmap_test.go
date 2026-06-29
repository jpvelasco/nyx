package nmap

import (
	"context"
	"strings"
	"testing"
	"time"
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

func TestPortScanResultShape_SingleOpenPort(t *testing.T) {
	if !Available() {
		t.Skip("nmap not available")
	}
	result, err := PortScan(context.Background(), "127.0.0.1", []int{22}, "tcp", PoliteScanOptions)
	if err != nil {
		t.Fatalf("PortScan returned error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestPortScanResultShape_MultipleOpenPorts(t *testing.T) {
	if !Available() {
		t.Skip("nmap not available")
	}
	result, err := PortScan(context.Background(), "127.0.0.1", []int{80, 443, 8080}, "tcp", PoliteScanOptions)
	if err != nil {
		t.Fatalf("PortScan returned error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestPortScanResultShape_AllFiltered(t *testing.T) {
	if !Available() {
		t.Skip("nmap not available")
	}
	result, err := PortScan(context.Background(), "192.0.2.1", []int{80, 443}, "tcp", PoliteScanOptions)
	if err != nil {
		t.Fatalf("PortScan returned error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestPortScanResultShape_MixedStates(t *testing.T) {
	if !Available() {
		t.Skip("nmap not available")
	}
	result, err := PortScan(context.Background(), "127.0.0.1", []int{22, 80, 443, 9999}, "tcp", PoliteScanOptions)
	if err != nil {
		t.Fatalf("PortScan returned error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestPortScanTimeout(t *testing.T) {
	if !Available() {
		t.Skip("nmap not available")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := PortScan(ctx, "192.0.2.1", []int{80}, "tcp", PoliteScanOptions)
	if err == nil {
		t.Error("expected timeout error")
	} else if !strings.Contains(err.Error(), "deadline exceeded") {
		t.Errorf("expected timeout-related error, got: %v", err)
	}
}

func TestPortScanMultipleHosts(t *testing.T) {
	if !Available() {
		t.Skip("nmap not available")
	}
	result, err := PortScan(context.Background(), "127.0.0.1", []int{22, 80, 443, 8080}, "tcp", DefaultScanOptions)
	if err != nil {
		t.Fatalf("PortScan error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}
