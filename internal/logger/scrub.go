package logger

import (
	"encoding/json"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// Redaction placeholders used by the export scrubber. A scrubbed artifact
// must stay human-legible, so every placeholder names what was removed.
const (
	redactIP    = "[ip]"
	redactCIDR  = "[cidr]"
	redactMAC   = "[mac]"
	redactHost  = "[host]"
	redactValue = "[redacted]"
)

// scrubKeyRe matches attribute keys whose values are never safe to export.
var scrubKeyRe = regexp.MustCompile(`(?i)secret|password|passwd|token|api_?key|credential|access_?key|private_?key|authorization`)

// scrubPatterns are the PII recognisers. Order of the passes matters: a
// CIDR before a bare IP (so "a.b.c.d/n" is not split into ip+suffix), a
// hostname before the token pass (a dotted name is not a token run), and
// token runs last so they see the post-address-substitution text. IPv6
// is detected by parsing candidates (ipv6CandRe) with net.ParseIP rather
// than by a bare colon pattern: a wall-clock "HH:MM:SS" then never looks
// like an address, and compressed forms ("2001:db8::1") are caught too.
var (
	// ipCIDRRe matches a bare IPv4 and an IPv4 CIDR in one pass. Handling
	// both together keeps a kept CIDR's base address from being re-read
	// as a bare IP in a later pass (which would redact it).
	ipCIDRRe   = regexp.MustCompile(`\b(\d{1,3}\.){3}\d{1,3}(?:/(3[0-2]|2[0-9]|1[0-9]|[0-9]))?\b`)
	ipv6CandRe = regexp.MustCompile(`(?i)\b[0-9a-f]*:(?::?[0-9a-f]*){1,8}\b`)
	macRe      = regexp.MustCompile(`\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b`)
	// hostRe is case-insensitive: DNS/PTR and controller client lists return
	// mixed-case names (DESKTOP-ABC.lan, NAS.Home.internal) that would
	// otherwise leak. scrubHost lowercases before the allowlist check, so
	// this does not widen the keep-list.
	hostRe = regexp.MustCompile(`(?i)\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+\.[a-z]{2,24}\b`)
	// tokenRunRe matches a run of at least 32 token-alphabet characters
	// (alphanumerics, '=', '+'). Hyphen is deliberately excluded:
	// hyphenated strings in nyx logs are labels and identifiers
	// ("bearer-<token>", "site-abc", file names) whose readable parts
	// must survive; the token proper is the long unbroken run. Whole
	// hex digests and base64-style tokens are 32+ unbroken runs and are
	// caught; short runs (trace ids, words, path segments) are not.
	tokenRunRe = regexp.MustCompile(`[A-Za-z0-9+=]{32,}`)
)

// docNets are the RFC 5737 documentation blocks, loopback, and the
// all-zeros literal. These are safe to keep by definition — the whole
// point of TEST-NET is that it can never identify a real network.
var docNets = []net.IPNet{
	{IP: net.IPv4(192, 0, 2, 0), Mask: net.CIDRMask(24, 32)},    // TEST-NET-1
	{IP: net.IPv4(198, 51, 100, 0), Mask: net.CIDRMask(24, 32)}, // TEST-NET-2
	{IP: net.IPv4(203, 0, 113, 0), Mask: net.CIDRMask(24, 32)},  // TEST-NET-3
	{IP: net.IPv4(127, 0, 0, 0), Mask: net.CIDRMask(8, 32)},     // loopback
	{IP: net.IPv4(0, 0, 0, 0), Mask: net.CIDRMask(32, 32)},      // 0.0.0.0 literal
}

// allowlistIPs are the exact host literals committed in examples/ and
// testdata/ (examples/homelab.yaml, testdata/valid_spec.yaml). This is a
// keep-list of fixture identities, not a range: an unlisted private IP is
// still redacted. TestAllowlistMatchesFixtures keeps the list in sync with
// the fixtures.
var allowlistIPs = []string{
	"10.0.10.1", "10.0.11.1", "10.0.20.1", "10.0.30.1",
	"10.0.40.1", "10.0.50.1", "10.0.60.1", "10.0.60.15",
	"10.0.20.15", "10.0.20.50", "10.0.50.5",
}

// allowlistCIDRs are the exact fixture CIDRs safe to keep. The broad
// VPN-route literals in the fixtures (10.0.0.0/8, 10.0.0.0/16) are
// deliberately excluded — they are route expectations, not host
// identities, and redacting them is the safe direction.
var allowlistCIDRs = []string{
	"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",
	"127.0.0.0/8", "0.0.0.0/0",
	"10.255.255.0/30",
}

// allowlistNames are hostnames safe to keep: the documentation-domain
// names from docs/naming.md plus loopback. Any *.example name is also
// kept (suffix rule, checked in scrubHost).
var allowlistNames = []string{
	"localhost",
	"nas.home.example",
}

// scrubReplacer is the PII classifier shared by all lines.
type scrubReplacer struct {
	ipSet   map[string]struct{}
	cidrSet map[string]struct{}
	nameSet map[string]struct{}
}

func newScrubReplacer() *scrubReplacer {
	r := &scrubReplacer{
		ipSet:   make(map[string]struct{}, len(allowlistIPs)),
		cidrSet: make(map[string]struct{}, len(allowlistCIDRs)),
		nameSet: make(map[string]struct{}, len(allowlistNames)),
	}
	for _, ip := range allowlistIPs {
		r.ipSet[ip] = struct{}{}
	}
	for _, c := range allowlistCIDRs {
		r.cidrSet[c] = struct{}{}
	}
	for _, n := range allowlistNames {
		r.nameSet[n] = struct{}{}
	}
	return r
}

var defaultReplacer = newScrubReplacer()

// normalizeIPv4 parses a dotted-quad literal (leading zeros allowed,
// which net.ParseIP rejects) into a 4-byte address.
func normalizeIPv4(s string) net.IP {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return nil
	}
	out := make(net.IP, 4)
	for i, p := range parts {
		if p == "" || len(p) > 3 {
			return nil
		}
		n := 0
		for j := range p {
			if p[j] < '0' || p[j] > '9' {
				return nil
			}
			n = n*10 + int(p[j]-'0')
		}
		if n > 255 {
			return nil
		}
		out[i] = byte(n)
	}
	return out
}

// IsAllowlistedIP reports whether ip (a dotted-quad) is on the export
// keep-list: a documentation/loopback address or an enumerated fixture
// literal.
func IsAllowlistedIP(ip string) bool {
	if _, ok := defaultReplacer.ipSet[ip]; ok {
		return true
	}
	ipp := normalizeIPv4(ip)
	if ipp == nil {
		return false
	}
	for i := range docNets {
		if docNets[i].Contains(ipp) {
			return true
		}
	}
	return false
}

// scrubText applies every PII pass to one string, in order.
func (r *scrubReplacer) scrubText(s string) string {
	// IPv4 / CIDR in one pass (see ipCIDRRe).
	s = ipCIDRRe.ReplaceAllStringFunc(s, func(m string) string {
		if strings.ContainsRune(m, '/') {
			return r.scrubCIDR(m)
		}
		return r.scrubIPv4(m)
	})
	for _, m := range macRe.FindAllString(s, -1) {
		s = strings.ReplaceAll(s, m, redactMAC)
	}
	// IPv6: scan loose hex:hex candidates and validate with
	// net.ParseIP — compressed forms ("2001:db8::1") and full forms are
	// both caught, while times ("08:00:00"), MACs, and other
	// colon-separated non-addresses parse to nil and are left alone.
	for _, m := range ipv6CandRe.FindAllString(s, -1) {
		// len(net.IP) is 16 only for true IPv6 (4 for v4, 0 for nil),
		// so the nil check is implicit.
		if ip := net.ParseIP(m); len(ip) == 16 {
			s = strings.ReplaceAll(s, m, redactIP)
		}
	}
	for _, m := range hostRe.FindAllString(s, -1) {
		if r.scrubHost(m) == redactHost {
			s = strings.ReplaceAll(s, m, redactHost)
		}
	}
	// Last pass: addresses and hosts are placeholders by now (or allowlisted
	// literals, which contain no 32+ token runs), so a long token run here is
	// secret material, not an identifier.
	return r.scrubTokens(s)
}

func (r *scrubReplacer) scrubIPv4(ip string) string {
	if IsAllowlistedIP(ip) {
		return ip
	}
	return redactIP
}

func (r *scrubReplacer) scrubCIDR(c string) string {
	if _, ok := r.cidrSet[c]; ok {
		return c
	}
	// A CIDR also keeps when it sits entirely inside a documentation
	// network: its mask is at least as tight as the block's and its
	// network address is inside the block (a /29 inside 192.0.2.0/24 is a
	// subset of the TEST-NET keep-block; 192.168.0.0/24 is not inside any
	// keep-block). ipCIDRRe only hands us a 0-32 mask, so the only real
	// guard left is a base whose quads exceed 255 (e.g. 999.1.1.1).
	base, maskStr, _ := strings.Cut(c, "/")
	maskBits, _ := strconv.Atoi(maskStr)
	ip := normalizeIPv4(base)
	if ip == nil {
		return redactCIDR
	}
	for i := range docNets {
		docOnes, _ := docNets[i].Mask.Size()
		if maskBits >= docOnes && docNets[i].Contains(ip) {
			return c
		}
	}
	return redactCIDR
}

func (r *scrubReplacer) scrubHost(h string) string {
	hl := strings.ToLower(h)
	if _, ok := r.nameSet[hl]; ok {
		return h
	}
	if strings.HasSuffix(hl, ".example") {
		return h
	}
	return redactHost
}

// scrubTokens redacts token-shaped runs: a hex digest or base64-style
// secret is a long unbroken run of token-alphabet characters, so redact
// at the run — a value like "bearer-<40 chars>" keeps its readable
// prefix and redacts the token. Short runs (trace ids, words, path
// segments) are below the 32-char floor and pass through.
func (r *scrubReplacer) scrubTokens(s string) string {
	return tokenRunRe.ReplaceAllString(s, redactValue)
}

// ScrubLine redacts PII from one serialized log line — a flat JSON object
// (the normal case) or raw text for hand-edited/truncated lines, which
// still get the regex pass so nothing slips through. PII is redacted in
// string values wherever they appear, and any value under a sensitive key
// is replaced wholesale. The output always ends in a newline; non-PII
// fields (event, method, path, attempt, timing, status) pass through
// unchanged.
func ScrubLine(line []byte) []byte {
	trimmed := strings.TrimRight(string(line), "\r\n")
	var obj map[string]any
	if json.Unmarshal([]byte(trimmed), &obj) != nil {
		return []byte(defaultReplacer.scrubText(trimmed) + "\n")
	}
	for k, v := range obj {
		if scrubKeyRe.MatchString(k) {
			obj[k] = redactValue
			continue
		}
		obj[k] = scrubJSONValue(v)
	}
	data, err := json.Marshal(obj)
	if err != nil {
		return []byte(defaultReplacer.scrubText(trimmed) + "\n")
	}
	return append(data, '\n')
}

// scrubJSONValue redacts a parsed JSON value. Only strings carry PII in a
// log line (numbers, bools, null are structural), but slices and objects
// are walked so a value nested one level deep is still reached.
func scrubJSONValue(v any) any {
	switch t := v.(type) {
	case string:
		return defaultReplacer.scrubText(t)
	case []any:
		out := make([]any, len(t))
		for i := range t {
			out[i] = scrubJSONValue(t[i])
		}
		return out
	case map[string]any:
		for k, vv := range t {
			if scrubKeyRe.MatchString(k) {
				t[k] = redactValue
				continue
			}
			t[k] = scrubJSONValue(vv)
		}
		return t
	default:
		return v
	}
}
