package recommendations

import (
	"testing"
)

// TestExtractInt tests integer extraction from various types
func TestExtractInt(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected int
	}{
		{"int", 42, 42},
		{"int32", int32(100), 100},
		{"int64", int64(200), 200},
		{"float64", float64(3.5), 3},
		{"float32", float32(4.9), 4},
		{"nil", nil, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractInt(tt.input)
			if result != tt.expected {
				t.Errorf("extractInt(%v) = %d; want %d", tt.input, result, tt.expected)
			}
		})
	}
}

// TestIpInCidr tests IP address validation against CIDR ranges
func TestIpInCidr(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		cidr     string
		expected bool
	}{
		{"valid_ip_in_cidr", "192.168.1.50", "192.168.1.0/24", true},
		{"invalid_ip_in_cidr", "192.168.2.50", "192.168.1.0/24", false},
		{"valid_ip_exact_match", "192.168.1.1", "192.168.1.1/32", true},
		{"invalid_ip_exact_match", "192.168.1.2", "192.168.1.1/32", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ipInCIDR(tt.ip, tt.cidr)
			if result != tt.expected {
				t.Errorf("ipInCIDR(%q, %q) = %v; want %v", tt.ip, tt.cidr, result, tt.expected)
			}
		})
	}
}

// TestParseIsolationTarget tests parsing of isolation target strings
func TestParseIsolationTarget(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected struct {
			from string
			to   string
		}
	}{
		{"valid_from_to", "personal -> gaming", struct{ from, to string }{from: "personal", to: "gaming"}},
		{"only_from", "personal", struct{ from, to string }{from: "", to: ""}},
		{"only_to", "gaming", struct{ from, to string }{from: "", to: ""}},
		{"empty_string", "", struct{ from, to string }{from: "", to: ""}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			from, to := parseIsolationTarget(tt.input)
			if from != tt.expected.from {
				t.Errorf("parseIsolationTarget(%q).From = %q; want %q", tt.input, from, tt.expected.from)
			}
			if to != tt.expected.to {
				t.Errorf("parseIsolationTarget(%q).To = %q; want %q", tt.input, to, tt.expected.to)
			}
		})
	}
}

// TestParseIsolationFromSummary tests parsing of isolation summary strings
func TestParseIsolationFromSummary(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected struct {
			from string
			to   string
		}
	}{
		{"valid_summary", "isolation violation: personal can reach gaming", struct{ from, to string }{from: "personal", to: "gaming"}},
		{"invalid_summary", "some other error message", struct{ from, to string }{from: "", to: ""}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			from, to := parseIsolationFromSummary(tt.input)
			if from != tt.expected.from {
				t.Errorf("parseIsolationFromSummary(%q).From = %q; want %q", tt.input, from, tt.expected.from)
			}
			if to != tt.expected.to {
				t.Errorf("parseIsolationFromSummary(%q).To = %q; want %q", tt.input, to, tt.expected.to)
			}
		})
	}
}
