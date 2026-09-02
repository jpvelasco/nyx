package logger

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// fixtureIPRe pulls host-identity literals (dotted quads) out of the
// committed spec fixtures, limited to the fields that name a host:
// gateways, probe hosts, assertion targets, expected IPs, and DNS
// servers. Network prefixes (cidr:, VPN routes) and public resolvers
// (8.8.8.8) are not host identities and are excluded.
var fixtureIPRe = regexp.MustCompile(`(?m)^\s*(?:gateway|target|host|expect_ip|server):\s*(\d{1,3}(?:\.\d{1,3}){3})\s*$`)

// collectFixtureIPs scans examples/ and testdata/ for the host-identity
// literals that a log line could legitimately carry.
func collectFixtureIPs(t *testing.T, roots []string) map[string]struct{} {
	t.Helper()
	found := map[string]struct{}{}
	for _, root := range roots {
		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatalf("reading fixture dir %s: %v", root, err)
		}
		for _, ent := range entries {
			if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".yaml") && !strings.HasSuffix(ent.Name(), ".yml") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(root, ent.Name())) // nosemgrep — fixture dir is a fixed repo path
			if err != nil {
				t.Fatalf("reading fixture %s: %v", ent.Name(), err)
			}
			for _, m := range fixtureIPRe.FindAllStringSubmatch(string(b), -1) {
				if m[1] == "8.8.8.8" { // public resolver, not a fixture identity
					continue
				}
				found[m[1]] = struct{}{}
			}
		}
	}
	return found
}

// TestAllowlistMatchesFixtures is the drift guard: the hardcoded
// allowlist must equal the host-identity literals in the committed
// fixtures. If a fixture changes, this test forces the allowlist to be
// updated in the same change.
func TestAllowlistMatchesFixtures(t *testing.T) {
	found := collectFixtureIPs(t, []string{"../../examples", "../../testdata"})

	allow := map[string]struct{}{}
	for _, ip := range allowlistIPs {
		allow[ip] = struct{}{}
	}

	// Every fixture host literal must be allowlisted; public resolvers
	// (8.8.8.8) were excluded at collection time.
	for ip := range found {
		if _, ok := allow[ip]; !ok {
			t.Errorf("fixture IP %s not in allowlist; update allowlistIPs or the fixture", ip)
		}
	}

	// Every allowlisted IP must appear in the fixtures (no stale entries).
	for ip := range allow {
		if _, ok := found[ip]; !ok {
			t.Errorf("allowlist IP %s not found in fixtures; update allowlistIPs or the fixture", ip)
		}
	}
}

func TestIsAllowlistedIP(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"192.0.2.1", true}, // TEST-NET-1
		{"198.51.100.7", true},
		{"203.0.113.255", true},
		{"127.0.0.1", true},
		{"127.9.9.9", true},
		{"0.0.0.0", true},
		{"10.0.10.1", true},  // fixture gateway
		{"10.0.60.15", true}, // fixture probe
		{"10.0.50.5", true},  // fixture media host
		{"10.0.99.5", false}, // unlisted 10.x
		{"192.168.5.4", false},
		{"172.16.0.9", false},
		{"8.8.8.8", false}, // public, unlisted
		{"999.1.1.1", false},
		{"10.0.10.1/24", false}, // not a dotted quad
	}
	for _, c := range cases {
		if got := IsAllowlistedIP(c.ip); got != c.want {
			t.Errorf("IsAllowlistedIP(%q) = %v, want %v", c.ip, got, c.want)
		}
	}
}

func TestScrubLine_IPsAndCIDRs(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			"private host redacted",
			`{"msg":"target 192.168.5.4 unreachable"}`,
			`{"msg":"target [ip] unreachable"}`,
		},
		{
			"public host redacted",
			`{"msg":"dnsserver 8.8.8.8"}`,
			`{"msg":"dnsserver [ip]"}`,
		},
		{
			"allowlisted fixture kept",
			`{"msg":"probe 10.0.60.15 ok"}`,
			`{"msg":"probe 10.0.60.15 ok"}`,
		},
		{
			"testnet kept",
			`{"msg":"doc 192.0.2.42"}`,
			`{"msg":"doc 192.0.2.42"}`,
		},
		{
			"live cidr redacted",
			`{"msg":"scan 192.168.0.0/24"}`,
			`{"msg":"scan [cidr]"}`,
		},
		{
			"broad route literal redacted",
			`{"msg":"route 10.0.0.0/8"}`,
			`{"msg":"route [cidr]"}`,
		},
		{
			"dead test range kept",
			`{"msg":"sweep 10.255.255.0/30"}`,
			`{"msg":"sweep 10.255.255.0/30"}`,
		},
		{
			"testnet cidr kept",
			`{"msg":"sweep 203.0.113.0/24"}`,
			`{"msg":"sweep 203.0.113.0/24"}`,
		},
		{
			"multiple mixed",
			`{"msg":"from 192.168.1.10 to 10.0.10.1 via 8.8.8.8"}`,
			`{"msg":"from [ip] to 10.0.10.1 via [ip]"}`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := strings.TrimRight(string(ScrubLine([]byte(c.in))), "\n")
			if got != c.want {
				t.Errorf("got\n%s\nwant\n%s", got, c.want)
			}
		})
	}
}

func TestScrubLine_HostnamesAndMACs(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			"real fqdn redacted",
			`{"msg":"resolved router.home.example-dsl.jpvelasco.net"}`,
			`{"msg":"resolved [host]"}`,
		},
		{
			"real fqdn redacted (short TLD)",
			`{"msg":"resolved dns.internal-homelab.com"}`,
			`{"msg":"resolved [host]"}`,
		},
		{
			"allowlisted example kept",
			`{"msg":"nas.home.example mounted"}`,
			`{"msg":"nas.home.example mounted"}`,
		},
		{
			"any example kept",
			`{"msg":"probe fe80.example ok"}`,
			`{"msg":"probe fe80.example ok"}`,
		},
		{
			"localhost kept",
			`{"msg":"loopback localhost"}`,
			`{"msg":"loopback localhost"}`,
		},
		{
			"mixed-case fqdn redacted",
			`{"msg":"resolved DESKTOP-ABC.home.lan"}`,
			`{"msg":"resolved [host]"}`,
		},
		{
			"mixed-case fqdn redacted (internal tld)",
			`{"msg":"peer NAS.Home.internal"}`,
			`{"msg":"peer [host]"}`,
		},
		{
			"two-label local name redacted",
			`{"msg":"leased nas.local from dhcp"}`,
			`{"msg":"leased [host] from dhcp"}`,
		},
		{
			"two-label lan name redacted (mixed case)",
			`{"msg":"peer Router.lan refused"}`,
			`{"msg":"peer [host] refused"}`,
		},
		{
			"file name with log extension kept",
			`{"msg":"wrote artifact nyx.log"}`,
			`{"msg":"wrote artifact nyx.log"}`,
		},
		{
			"file name with json extension kept",
			`{"msg":"loaded seen.json"}`,
			`{"msg":"loaded seen.json"}`,
		},
		{
			"file name with yaml extension kept",
			`{"msg":"spec homelab.yaml ok"}`,
			`{"msg":"spec homelab.yaml ok"}`,
		},
		{
			"path file name with json extension kept",
			`{"msg":"snapshot saved path=baseline.json"}`,
			`{"msg":"snapshot saved path=baseline.json"}`,
		},
		{
			"mixed-case file extension kept",
			`{"msg":"wrote NYX.LOG"}`,
			`{"msg":"wrote NYX.LOG"}`,
		},
		{
			"mac redacted",
			`{"msg":"lease aa:bb:cc:dd:ee:01"}`,
			`{"msg":"lease [mac]"}`,
		},
		{
			"ipv6 redacted",
			`{"msg":"link 2001:db8::1"}`,
			`{"msg":"link [ip]"}`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := strings.TrimRight(string(ScrubLine([]byte(c.in))), "\n")
			if got != c.want {
				t.Errorf("got\n%s\nwant\n%s", got, c.want)
			}
		})
	}
}

func TestScrubLine_SecretKeysAndTokens(t *testing.T) {
	// Any key in the blocklist is replaced wholesale, whatever its value.
	// The secret value is built, not literal, so scanners never see a
	// hardcoded-credential-shaped string in this file.
	secret := strings.Repeat("0123456789abcdef", 2)
	in := `{"api_key":"small","client_secret":"long-` + secret + `","msg":"ok"}`
	got := strings.TrimRight(string(ScrubLine([]byte(in))), "\n")
	want := `{"api_key":"[redacted]","client_secret":"[redacted]","msg":"ok"}`
	if got != want {
		t.Errorf("got %s want %s", got, want)
	}

	// A long high-entropy value under a non-sensitive key is still
	// redacted.
	token := strings.Repeat("a", 40)
	in2 := `{"msg":"bearer-` + token + `"}`
	got2 := strings.TrimRight(string(ScrubLine([]byte(in2))), "\n")
	want2 := `{"msg":"bearer-[redacted]"}`
	if got2 != want2 {
		t.Errorf("got %s want %s", got2, want2)
	}

	// A long path with slashes is NOT token material: it must survive.
	path := "/openapi/v1/sites/site-abc123/switches/sw-456/ports/22"
	in3 := `{"method":"POST","path":"` + path + `","status":200}`
	got3 := strings.TrimRight(string(ScrubLine([]byte(in3))), "\n")
	if !strings.Contains(got3, path) {
		t.Errorf("path must survive scrubbing, got %s", got3)
	}
}

// TestScrubLine_CIDREdgeCases pins the CIDR pass boundaries. ipCIDRRe
// only hands scrubCIDR a 0-32 mask (a wider suffix makes the regex
// backtrack to the bare dotted quad, which is redacted on its own while
// the suffix stays visible), so the only scrubCIDR guard a line can hit
// is a base whose quads exceed 255.
func TestScrubLine_CIDREdgeCases(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"quad over 255 redacts the whole cidr", `{"msg":"x 999.1.1.1/24"}`, `{"msg":"x [cidr]"}`},
		{"mask over 32 falls back to ip redaction", `{"msg":"x 1.2.3.4/40"}`, `{"msg":"x [ip]/40"}`},
		{"bad mask falls back to ip redaction", `{"msg":"x 1.2.3.4/bad"}`, `{"msg":"x [ip]/bad"}`},
		{"mask exactly 32 kept in docnet", `{"msg":"x 192.0.2.7/32"}`, `{"msg":"x 192.0.2.7/32"}`},
		{"tighter docnet subset kept", `{"msg":"x 203.0.113.16/29"}`, `{"msg":"x 203.0.113.16/29"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := strings.TrimRight(string(ScrubLine([]byte(c.in))), "\n")
			if got != c.want {
				t.Errorf("got %s want %s", got, c.want)
			}
		})
	}
}

// TestScrubLine_TokenRunEdgeCases: a bare hex digest of exactly the 32-char
// floor is redacted; a 31-char run is below the floor and survives.
func TestScrubLine_TokenRunEdgeCases(t *testing.T) {
	// Exactly the 32-char floor is redacted.
	in := `{"msg":"h ` + strings.Repeat("a", 32) + ` k"}`
	got := string(ScrubLine([]byte(in)))
	if !strings.Contains(got, "[redacted]") {
		t.Errorf("32-char hex run must be redacted, got %s", got)
	}
	// A 31-char run is below the floor and survives verbatim.
	run31 := strings.Repeat("b", 31)
	in2 := `{"msg":"h ` + run31 + ` k"}`
	got2 := string(ScrubLine([]byte(in2)))
	if strings.Contains(got2, "[redacted]") {
		t.Errorf("31-char run must not be redacted, got %s", got2)
	}
	if !strings.Contains(got2, run31) {
		t.Errorf("31-char run must survive, got %s", got2)
	}
}

// TestNormalizeIPv4_BadQuads: non-4-part, >255, non-digit, long-part, and
// empty-part inputs all parse to nil; a valid quad with leading zeros
// (which net.ParseIP rejects) parses fine.
func TestNormalizeIPv4_BadQuads(t *testing.T) {
	for _, s := range []string{
		"1.2.3", "1.2.3.4.5", "1.2.3.0999", "1.2.3.x", "300.1.1.1", "1..2.3",
	} {
		if ip := normalizeIPv4(s); ip != nil {
			t.Errorf("normalizeIPv4(%q) = %v, want nil", s, ip)
		}
	}
	// Leading zeros are accepted by the custom parser (not net.ParseIP).
	if ip := normalizeIPv4("127.0.0.01"); ip == nil {
		t.Errorf("normalizeIPv4(\"127.0.0.01\") = nil, want 4-byte loopback")
	} else if !IsAllowlistedIP("127.0.0.01") {
		t.Errorf("127.0.0.01 (leading zero) should be allowlisted via loopback docnet")
	}
}

func TestScrubLine_DiagnosticFieldsSurvive(t *testing.T) {
	in := `{"ts":"2026-09-01T08:00:00.000Z","level":"warn","msg":"omada","cmd":"omada","event":"retry","method":"POST","path":"/openapi/v1/token","attempt":2,"delay_ms":500,"status":503,"trace_id":"a1b2c3d4","error":"transport or protocol error","service.name":"nyx","version":"v0.4.0"}`
	out := string(ScrubLine([]byte(in)))
	for _, field := range []string{
		`"ts":"2026-09-01T08:00:00.000Z"`,
		`"level":"warn"`,
		`"event":"retry"`,
		`"method":"POST"`,
		`"path":"/openapi/v1/token"`,
		`"attempt":2`,
		`"delay_ms":500`,
		`"status":503`,
		`"trace_id":"a1b2c3d4"`,
		`"error":"transport or protocol error"`,
		`"service.name":"nyx"`,
		`"version":"v0.4.0"`,
	} {
		if !strings.Contains(out, field) {
			t.Errorf("diagnostic field missing from output:\n%s\nexpected %q in it", out, field)
		}
	}
}

// TestScrubLine_TraceIDSurvivesTokenFloor pins the correlation-identity
// assumption: NewTraceID emits an 8-hex-char id (TestNewTraceID), far
// below the 32-char token floor, so per-run trace ids survive scrubbing
// and a scrubbed artifact stays correlatable.
func TestScrubLine_TraceIDSurvivesTokenFloor(t *testing.T) {
	in := `{"level":"info","msg":"run","trace_id":"` + NewTraceID() + `"}`
	out := string(ScrubLine([]byte(in)))
	if strings.Contains(out, "[redacted]") {
		t.Errorf("8-char trace id must not be redacted, got %s", out)
	}
	// A real 16-byte OTel trace id (32 hex chars) is still redacted —
	// that shape is indistinguishable from a token run.
	long := `{"trace_id":"` + strings.Repeat("a", 32) + `"}`
	if !strings.Contains(string(ScrubLine([]byte(long))), "[redacted]") {
		t.Errorf("32-hex id must be redacted, got %s", long)
	}
}

// TestScrubLine_LargeIntegerSurvives pins that large integer fields are
// re-emitted exactly (json.Number), not as float64 scientific notation.
func TestScrubLine_LargeIntegerSurvives(t *testing.T) {
	in := `{"level":"info","msg":"counter","count_ns":1735689600000000000,"attempt":2}`
	out := string(ScrubLine([]byte(in)))
	if !strings.Contains(out, `"count_ns":1735689600000000000`) {
		t.Errorf("large integer must round-trip exactly, got %s", out)
	}
	if strings.Contains(out, "e+18") || strings.Contains(out, "e+19") {
		t.Errorf("large integer must not use scientific notation, got %s", out)
	}
}

func TestScrubLine_RawTextFallback(t *testing.T) {
	in := "manual note: controller was at 192.168.1.254 and gw router.myhome.org"
	out := string(ScrubLine([]byte(in)))
	if !strings.Contains(out, "[ip]") || !strings.Contains(out, "[host]") {
		t.Errorf("raw fallback should redact ip and host, got %q", out)
	}
	// RFC3339 timestamps and bare time-of-day substrings must not be
	// read as IPv6.
	in2 := `{"ts":"2026-09-01T08:00:00.000Z","msg":"t 08:00:00"}`
	out2 := string(ScrubLine([]byte(in2)))
	if strings.Contains(out2, "[ip]") {
		t.Errorf("time-of-day must not be redacted as IPv6, got %q", out2)
	}
	if !strings.Contains(out2, `"ts":"2026-09-01T08:00:00.000Z"`) {
		t.Errorf("RFC3339 timestamp must survive intact, got %q", out2)
	}
}

func TestScrubLine_EndsInNewline(t *testing.T) {
	out := ScrubLine([]byte(`{"msg":"x"}`))
	if len(out) == 0 || out[len(out)-1] != '\n' {
		t.Errorf("output must end in a newline, got %q", out)
	}
}

func TestScrubLine_NonStringValuesUntouched(t *testing.T) {
	in := `{"count":42,"ok":true,"none":null,"msg":"fine"}`
	out := string(ScrubLine([]byte(in)))
	if !strings.Contains(out, `"count":42`) || !strings.Contains(out, `"ok":true`) || !strings.Contains(out, `"none":null`) {
		t.Errorf("non-string values must pass through, got %s", out)
	}
}

func TestScrubLine_NestedStructures(t *testing.T) {
	in := `{"msg":"group","data":{"host":"192.168.9.9"},"list":["192.168.9.10","aa:bb:cc:dd:ee:02"]}`
	out := string(ScrubLine([]byte(in)))
	if strings.Contains(out, "192.168.9.") || strings.Contains(out, "aa:bb:cc:dd:ee:02") {
		t.Errorf("nested values must be redacted, got %s", out)
	}

	// A sensitive key nested inside an object (not at the top level) is
	// also replaced wholesale by the map walker.
	in2 := `{"msg":"outer","data":{"client_secret":"x1","note":"keep"}}`
	out2 := strings.TrimRight(string(ScrubLine([]byte(in2))), "\n")
	if !strings.Contains(out2, `"client_secret":"[redacted]"`) || !strings.Contains(out2, `"note":"keep"`) {
		t.Errorf("nested sensitive key must be redacted, non-sensitive kept, got %s", out2)
	}
}

// TestScrubHost_Direct exercises both arms of the hostname classifier:
// allowlisted names are kept, anything else is redacted.
func TestScrubHost_Direct(t *testing.T) {
	if got := defaultReplacer.scrubHost("NAS.Home.Example"); got != "NAS.Home.Example" {
		t.Errorf("scrubHost(allowlisted) = %q, want kept", got)
	}
	if got := defaultReplacer.scrubHost("sub.domain.example"); got != "sub.domain.example" {
		t.Errorf("scrubHost(.example suffix) = %q, want kept", got)
	}
	if got := defaultReplacer.scrubHost("router.mylan.local"); got != redactHost {
		t.Errorf("scrubHost(real fqdn) = %q, want %s", got, redactHost)
	}
}

// readFixtureLines returns the raw lines of the committed examples spec —
// used by tests that assert scrub and keep of the real fixture values.
