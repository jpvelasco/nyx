package intent

import (
	"testing"
)

// --- ValidateTarget ---

func TestValidateTarget_Valid(t *testing.T) {
	valid := []string{
		"10.0.10.1",
		"8.8.8.8",
		"::1",
		"2001:db8::1",
		"nas.example",
		"nas.home.example",
		"nas.example.", // absolute (FQDN) form
		"host-01.lab",
		"my_host.local", // mDNS-style underscore label
		"a.b.c.d",
	}
	for _, v := range valid {
		if err := ValidateTarget(v); err != nil {
			t.Errorf("ValidateTarget(%q) = %v, want nil", v, err)
		}
	}
}

func TestValidateTarget_DashPrefixed(t *testing.T) {
	invalid := []string{
		"-n 3",
		"-w 2000",
		"-I eth0",
		"--version",
		"-O host",
	}
	for _, v := range invalid {
		if err := ValidateTarget(v); err == nil {
			t.Errorf("ValidateTarget(%q) = nil, want error for dash-prefixed value", v)
		}
	}
}

func TestValidateTarget_PlusAndAtPrefixed(t *testing.T) {
	// '+' and '@' are dig option markers (+short, @server); rejected for targets too.
	for _, v := range []string{"+short", "+dnssec", "@8.8.8.8", "@server"} {
		if err := ValidateTarget(v); err == nil {
			t.Errorf("ValidateTarget(%q) = nil, want error", v)
		}
	}
}

func TestValidateTarget_InvalidHostOrIP(t *testing.T) {
	// None of these are a valid IP, and none is a valid hostname: a CIDR,
	// whitespace, a control character, an '@', or a malformed label.
	invalid := []string{
		"",
		"10.0.0.0/24",        // CIDR is not a ping/dig target
		"host with space",    // whitespace
		"bad\thost",          // tab control character
		"bad\nhost",          // newline
		"-bad-label.example", // label starts with '-'
		"host-.example",      // label ends with '-'
		"no@at.example",      // '@' is not a hostname character
	}
	for _, v := range invalid {
		if err := ValidateTarget(v); err == nil {
			t.Errorf("ValidateTarget(%q) = nil, want error", v)
		}
	}
}

func TestValidateTarget_EmptyLabel(t *testing.T) {
	for _, v := range []string{"host..example", "a...b"} {
		if err := ValidateTarget(v); err == nil {
			t.Errorf("ValidateTarget(%q) = nil, want error for empty label", v)
		}
	}
}

// --- ValidateServer ---

func TestValidateServer_Valid(t *testing.T) {
	valid := []string{
		"10.0.10.1",
		"10.0.10.1:5353", // explicit port
		"8.8.8.8:53",
		"resolver.example",
		"[::1]",    // bracketed IPv6
		"[::1]:53", // bracketed IPv6 with port
		"resolver.example:5353",
	}
	for _, v := range valid {
		if err := ValidateServer(v); err != nil {
			t.Errorf("ValidateServer(%q) = %v, want nil", v, err)
		}
	}
}

func TestValidateServer_Invalid(t *testing.T) {
	invalid := []string{
		"-n",
		"-host",
		"@8.8.8.8",
		"+short",
		"host with space:53",
		"10.0.0.0/24",
		"[::1:bad", // malformed brackets (not a parseable host:port)
	}
	for _, v := range invalid {
		if err := ValidateServer(v); err == nil {
			t.Errorf("ValidateServer(%q) = nil, want error", v)
		}
	}
}

func TestValidateServer_BadHostInHostPort(t *testing.T) {
	// A host:port whose host is not a valid host must be rejected.
	for _, v := range []string{"-bad:53", "with space:53"} {
		if err := ValidateServer(v); err == nil {
			t.Errorf("ValidateServer(%q) = nil, want error", v)
		}
	}
}

// --- Spec-level wiring: dns_check / network_health ---

func TestValidateSpec_DNSCheckBadQuery(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test",
		Assertions: []Assertion{{Type: "dns_check", Query: "-n"}}}
	err := ValidateSpec(spec)
	if err == nil || !contains(err.Error(), "dns_check") {
		t.Fatalf("expected dns_check query error, got %v", err)
	}
}

func TestValidateSpec_DNSCheckBadServer(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test",
		Assertions: []Assertion{{Type: "dns_check", Query: "nas.example", Server: "@8.8.8.8"}}}
	err := ValidateSpec(spec)
	if err == nil || !contains(err.Error(), "dns_check") {
		t.Fatalf("expected dns_check server error, got %v", err)
	}
}

func TestValidateSpec_NetworkHealthBadTarget(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test",
		Assertions: []Assertion{{Type: "network_health", Target: "-w 2000"}}}
	err := ValidateSpec(spec)
	if err == nil || !contains(err.Error(), "network_health") {
		t.Fatalf("expected network_health target error, got %v", err)
	}
}

func TestValidateSpec_DNSCheckValid(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test",
		Assertions: []Assertion{{Type: "dns_check", Query: "nas.example", Server: "10.0.10.1"}}}
	if err := ValidateSpec(spec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateSpec_NetworkHealthValid(t *testing.T) {
	spec := &Spec{Version: 1, Site: "test",
		Assertions: []Assertion{{Type: "network_health", Target: "10.0.10.1"}}}
	if err := ValidateSpec(spec); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
