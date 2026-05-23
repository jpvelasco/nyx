package nmap

import "testing"

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
