package dns

import (
	"context"
	"net"
	"regexp"
	"testing"
	"time"

	"github.com/jpvelasco/nyx/internal/models"
)

const dnsTimeout = 5 * time.Second

func dnsCtx() context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	// cancel is deferred by the test runner's process exit;
	// each call site that needs explicit cleanup creates its own context.
	//nolint:errcheck // cancel intentionally not deferred here — tests are short-lived
	_ = cancel
	return ctx
}

// =====================================================================
// resolve — internal helper
// =====================================================================

func TestResolveLocalhost_SystemResolver(t *testing.T) {
	result, ips, err := resolve(dnsCtx(), "localhost", "")
	if err != nil {
		t.Fatalf("resolve returned error: %v", err)
	}
	if result.Status == models.StatusError {
		t.Skipf("DNS resolution not available: %s", result.Summary)
	}
	if result.Status != models.StatusPass {
		t.Fatalf("expected pass, got %s: %s", result.Status, result.Summary)
	}
	if len(ips) == 0 {
		t.Fatal("expected at least one resolved IP")
	}
	// Verify observed fields
	if result.Observed["query"] != "localhost" {
		t.Errorf("expected query 'localhost', got %q", result.Observed["query"])
	}
	if result.Observed["server"] != "" {
		t.Errorf("expected empty server, got %q", result.Observed["server"])
	}
	if result.CheckType != "dns_check" {
		t.Errorf("expected check_type 'dns_check', got %q", result.CheckType)
	}
	if len(result.Evidence) == 0 {
		t.Error("expected at least one evidence entry")
	}
}

func TestResolve_UnresolvableHost_SystemResolver(t *testing.T) {
	result, ips, err := resolve(dnsCtx(), "this-hostname-does-not-exist-xyz123.invalid", "")
	if err != nil {
		t.Fatalf("resolve returned error: %v", err)
	}
	if result.Status != models.StatusError {
		t.Errorf("expected error for unresolvable host, got %s: %s", result.Status, result.Summary)
	}
	if len(ips) != 0 {
		t.Error("expected no IPs for failed resolution")
	}
}

func TestResolve_CustomResolver(t *testing.T) {
	result, ips, err := resolve(dnsCtx(), "localhost", "127.0.0.1")
	if err != nil {
		t.Fatalf("resolve returned error: %v", err)
	}
	if result.Status == models.StatusError {
		t.Skipf("Custom resolver not available: %s", result.Summary)
	}
	if result.Status != models.StatusPass {
		t.Fatalf("expected pass, got %s: %s", result.Status, result.Summary)
	}
	if len(ips) == 0 {
		t.Fatal("expected at least one resolved IP")
	}
	if result.Observed["server"] != "127.0.0.1" {
		t.Errorf("expected server '127.0.0.1', got %q", result.Observed["server"])
	}
}

func TestResolve_CustomResolver_Unreachable(t *testing.T) {
	// 192.0.2.1 is TEST-NET-1 — should timeout fast with context deadline
	// Use a hostname that won't resolve as a local alias (unlike "localhost")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, ips, err := resolve(ctx, "nonexistent-internal-host.local", "192.0.2.1")
	if err != nil {
		t.Fatalf("resolve returned error: %v", err)
	}
	if result.Status != models.StatusError {
		t.Errorf("expected error for unreachable resolver, got %s: %s", result.Status, result.Summary)
	}
	if len(ips) != 0 {
		t.Error("expected no IPs for failed resolution")
	}
}

func TestResolve_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	// Use a custom resolver with an unreachable server AND a hostname not in /etc/hosts.
	// Go's pure-Go resolver falls back to the system resolver when the custom dial fails,
	// and on Linux the system resolver reads /etc/hosts synchronously (ignoring context).
	// "nonexistent.example" won't resolve via any path, ensuring the error is returned.
	result, ips, err := resolve(ctx, "nonexistent.example", "192.0.2.1")
	if err != nil {
		t.Fatalf("resolve returned error: %v", err)
	}
	if result.Status != models.StatusError {
		t.Errorf("expected error for unreachable resolver, got %s: %s", result.Status, result.Summary)
	}
	if len(ips) != 0 {
		t.Error("expected no IPs for unreachable resolver")
	}
}

// =====================================================================
// Resolve — public wrapper
// =====================================================================

func TestResolveLocalhost(t *testing.T) {
	result, err := Resolve(dnsCtx(), "localhost", "")
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if result.Status == models.StatusError {
		t.Skipf("DNS resolution not available in this environment: %s", result.Summary)
	}
	if result.CheckType != "dns_check" {
		t.Errorf("expected check_type 'dns_check', got %q", result.CheckType)
	}
	_, ok := result.Observed["ips"]
	if !ok {
		t.Error("expected 'ips' in Observed")
	}
	// Verify Finish() was called (duration set)
	if result.DurationMs < 0 {
		t.Error("expected non-negative duration after Finish()")
	}
	if result.FinishedAt.IsZero() {
		t.Error("expected FinishedAt to be set after Finish()")
	}
}

// =====================================================================
// ResolveExpect
// =====================================================================

func TestResolveExpectMatch(t *testing.T) {
	result, err := ResolveExpect(dnsCtx(), "localhost", "", "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status == models.StatusError {
		t.Skipf("DNS not available: %s", result.Summary)
	}
	if result.Status != models.StatusPass {
		t.Errorf("expected pass for localhost→127.0.0.1, got %s: %s", result.Status, result.Summary)
	}
	if result.Expected["ip"] != "127.0.0.1" {
		t.Errorf("expected Expected['ip'] == '127.0.0.1', got %v", result.Expected["ip"])
	}
}

func TestResolveExpectMismatch(t *testing.T) {
	result, err := ResolveExpect(dnsCtx(), "localhost", "", "1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status == models.StatusError {
		t.Skipf("DNS not available: %s", result.Summary)
	}
	if result.Status != models.StatusFail {
		t.Errorf("expected fail for localhost→1.2.3.4 mismatch, got %s", result.Status)
	}
	if len(result.Violations) == 0 {
		t.Error("expected violations for mismatch")
	}
}

func TestResolveExpect_ResolutionError(t *testing.T) {
	// When resolution fails, the error result should propagate through
	result, err := ResolveExpect(dnsCtx(), "this-hostname-does-not-exist-xyz123.invalid", "", "1.2.3.4")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusError {
		t.Errorf("expected error when resolution fails, got %s: %s", result.Status, result.Summary)
	}
}

// =====================================================================
// CheckAvailable / Available
// =====================================================================

func TestCheckAvailable(t *testing.T) {
	err := CheckAvailable()
	// dig may or may not be installed — either outcome is valid
	if err == nil {
		t.Log("dig is available")
	} else {
		// dig is not available — verify error message is informative
		t.Logf("dig not available (expected in some environments): %v", err)
	}
}

func TestAvailable(t *testing.T) {
	hasDig := Available()
	t.Logf("Available() = %v", hasDig)

	// Verify Available and CheckAvailable are consistent
	err := CheckAvailable()
	hasDigFromCheck := err == nil
	if hasDig != hasDigFromCheck {
		t.Errorf("Available()=%v inconsistent with CheckAvailable()=%v", hasDig, hasDigFromCheck)
	}
}

// =====================================================================
// CheckDNSSEC
// =====================================================================

func TestCheckDNSSEC_NoDig(t *testing.T) {
	// If dig is not available, CheckDNSSEC should return error
	if Available() {
		t.Skip("dig is available, skipping no-dig test")
	}

	result, err := CheckDNSSEC(dnsCtx(), "example.com", "")
	if err != nil {
		t.Fatalf("CheckDNSSEC returned error: %v", err)
	}
	if result.Status != models.StatusError {
		t.Errorf("expected error when dig is not available, got %s: %s", result.Status, result.Summary)
	}
	if result.Summary != "dig is not installed or not in PATH" {
		t.Errorf("expected specific error message, got: %s", result.Summary)
	}
}

func TestCheckDNSSEC_WithDig(t *testing.T) {
	if !Available() {
		t.Skip("dig not available, skipping DNSSEC test")
	}

	result, err := CheckDNSSEC(dnsCtx(), "example.com", "")
	if err != nil {
		t.Fatalf("CheckDNSSEC returned error: %v", err)
	}

	// Result should be one of: pass (validated), warn (undetermined), or fail (bogus/servfail)
	validStatuses := map[models.Status]bool{
		models.StatusPass: true,
		models.StatusWarn: true,
		models.StatusFail: true,
	}
	if !validStatuses[result.Status] {
		t.Errorf("unexpected status %s, expected pass/warn/fail", result.Status)
	}

	// Verify structure
	if result.CheckType != "dns_check" {
		t.Errorf("expected check_type 'dns_check', got %q", result.CheckType)
	}
	if result.Observed["query"] != "example.com" {
		t.Errorf("expected query 'example.com', got %q", result.Observed["query"])
	}
	if result.Observed["server"] != "" {
		t.Errorf("expected empty server, got %q", result.Observed["server"])
	}
	if len(result.Evidence) == 0 {
		t.Error("expected evidence from dig output")
	}
	if result.FinishedAt.IsZero() {
		t.Error("expected FinishedAt to be set")
	}
}

func TestCheckDNSSEC_WithServer(t *testing.T) {
	if !Available() {
		t.Skip("dig not available, skipping DNSSEC test")
	}

	result, err := CheckDNSSEC(dnsCtx(), "example.com", "127.0.0.1")
	if err != nil {
		t.Fatalf("CheckDNSSEC returned error: %v", err)
	}

	// Even if the resolver doesn't support DNSSEC, we should get a result
	validStatuses := map[models.Status]bool{
		models.StatusPass: true,
		models.StatusWarn: true,
		models.StatusFail: true,
	}
	if !validStatuses[result.Status] {
		t.Errorf("unexpected status %s, expected pass/warn/fail", result.Status)
	}
	if result.Observed["server"] != "127.0.0.1" {
		t.Errorf("expected server '127.0.0.1', got %q", result.Observed["server"])
	}
}

// =====================================================================
// Regex pattern tests — verify DNSSEC output parsing
// =====================================================================

func TestRegexPatterns(t *testing.T) {
	tests := []struct {
		name    string
		pattern *regexp.Regexp
		input   string
		matches bool
	}{
		// reDigBogus
		{"bogus match", reDigBogus, ";  status: BOGUS", true},
		{"bogus no match", reDigBogus, ";  status: NOERROR", false},
		// reDigServFail
		{"servfail match", reDigServFail, ";  status: SERVFAIL", true},
		{"servfail no match", reDigServFail, ";  status: NOERROR", false},
		// reDigNoError
		{"noerror match", reDigNoError, ";  status: NOERROR", true},
		{"noerror no match", reDigNoError, ";  status: SERVFAIL", false},
		// reDigValidated
		{"validated match", reDigValidated, ";  status: VALIDATED", true},
		{"validated no match", reDigValidated, ";  status: NOERROR", false},
		// reRRSIG
		{"rrsig match", reRRSIG, "example.com. 300 IN RRSIG A 8 0 300", true},
		{"rrsig no match", reRRSIG, "example.com. 300 IN A 1.2.3.4", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.pattern.MatchString(tt.input)
			if got != tt.matches {
				t.Errorf("pattern match: got %v, want %v for input %q", got, tt.matches, tt.input)
			}
		})
	}
}

func TestRegexPatterns_MultiLine(t *testing.T) {
	// Simulate realistic dig output with DNSSEC validation lines.
	// The status regexes match lines like ";  status: NOERROR" from dig's
	// DNSSEC validation output (not the header line which uses different formatting).
	digOutput := `; <<>> DiG 9.18.1 <<>> +dnssec +sigchase example.com
;; global options: +cmd
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12345
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 3

;; QUESTION SECTION:
;example.com.			IN	A

;; ANSWER SECTION:
example.com.		300	IN	A	93.184.216.34
example.com.		300	IN	RRSIG	A 8 0 300 20260801000000 20260601000000 12345

;; ADDITIONAL SECTION:
example.com.		300	IN	DNSKEY	257 3 8 abcdef
;  status: VALIDATED`

	if !reDigValidated.MatchString(digOutput) {
		t.Error("expected VALIDATED match in multi-line dig output")
	}
	if !reRRSIG.MatchString(digOutput) {
		t.Error("expected RRSIG match in multi-line dig output")
	}
	if reDigBogus.MatchString(digOutput) {
		t.Error("expected no BOGUS match in multi-line dig output")
	}
	if reDigServFail.MatchString(digOutput) {
		t.Error("expected no SERVFAIL match in multi-line dig output")
	}
}

// =====================================================================
// Edge cases
// =====================================================================

func TestResolve_EmptyQuery(t *testing.T) {
	result, ips, err := resolve(dnsCtx(), "", "")
	if err != nil {
		t.Fatalf("resolve returned error: %v", err)
	}
	// Empty query will fail resolution
	if result.Status != models.StatusError {
		t.Errorf("expected error for empty query, got %s: %s", result.Status, result.Summary)
	}
	if len(ips) != 0 {
		t.Error("expected no IPs for empty query")
	}
}

func TestResolve_MultipleIPs(t *testing.T) {
	result, ips, err := resolve(dnsCtx(), "google.com", "")
	if err != nil {
		t.Fatalf("resolve returned error: %v", err)
	}
	if result.Status == models.StatusError {
		t.Skipf("DNS resolution not available: %s", result.Summary)
	}
	if result.Status != models.StatusPass {
		t.Fatalf("expected pass, got %s: %s", result.Status, result.Summary)
	}
	if len(ips) == 0 {
		t.Error("expected at least one IP from google.com")
	}
	for _, ip := range ips {
		if net.ParseIP(ip) == nil {
			t.Errorf("invalid IP in results: %s", ip)
		}
	}
}

func TestResolveExpect_MultipleIPs_ExpectedAbsent(t *testing.T) {
	result, err := ResolveExpect(dnsCtx(), "localhost", "", "192.168.1.100")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status == models.StatusError {
		t.Skipf("DNS not available: %s", result.Summary)
	}
	if result.Status != models.StatusFail {
		t.Errorf("expected fail, got %s: %s", result.Status, result.Summary)
	}
	if len(result.Violations) == 0 {
		t.Error("expected violations")
	}
}