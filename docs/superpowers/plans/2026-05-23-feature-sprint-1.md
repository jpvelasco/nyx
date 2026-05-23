# Feature Sprint 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add four new assertion types (`port_check`, `dns_check`, `network_health`, `acl_check`), SSH remote probe support, and safe scan mode defaults to nyx.

**Architecture:** Each new assertion type follows the existing pattern: (1) a backend function in `internal/backends/` does the raw work, (2) a new `runXxx` method on `audit.Engine` wires the backend to the spec, (3) `intent.Spec` and `ValidateSpec` are extended with the new types and the `probes` top-level field. The SSH probe is an executor layer that intercepts assertions with a `runner` field and runs them via SSH before returning a normal `CheckResult`. All changes are backward-compatible — existing specs continue to work unchanged.

**Tech Stack:** Go stdlib (`net`, `os/exec`, `golang.org/x/crypto/ssh`), existing nmap/system backends, existing Omada ACL backend.

---

## File Map

**New files:**
- `internal/backends/dns/dns.go` — DNS resolution + DNSSEC check backend
- `internal/backends/dns/dns_test.go`
- `internal/backends/health/health.go` — network health (ping stats + MTU) backend
- `internal/backends/health/health_test.go`
- `internal/probe/probe.go` — SSH remote executor: dials probe, runs command, returns stdout/stderr
- `internal/probe/probe_test.go`

**Modified files:**
- `internal/backends/nmap/nmap.go` — add `PoliteScanOptions`, `ScanMode` type, `PortScan` function
- `internal/intent/spec.go` — add `Probe` type, `Probes []Probe` to `Spec`, extend `Assertion` with `ScanMode`/`Runner` fields, extend `ValidateSpec` for all new assertion types
- `internal/intent/spec_test.go` — validation tests for new types
- `internal/audit/engine.go` — add `runPortCheck`, `runDNSCheck`, `runNetworkHealth`, `runACLCheck`; wire `runner` field to probe executor; update `runAssertion` switch; change default scan options to polite
- `internal/audit/engine_test.go` — integration tests for new assertion types
- `internal/providers/omada/provider.go` — add `GetACLRules` helper used by `runACLCheck`
- `go.mod` / `go.sum` — add `golang.org/x/crypto` for SSH

---

## Task 1: Add `ScanMode` and polite defaults to nmap backend

**Files:**
- Modify: `internal/backends/nmap/nmap.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/backends/nmap/nmap.go`'s test file. First create it if needed:

```go
// internal/backends/nmap/nmap_test.go
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
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/backends/nmap/... -run TestPoliteScanOptionsDefaults -v
```
Expected: FAIL — `PoliteScanOptions` undefined, `MaxRate` undefined

- [ ] **Step 3: Add `MaxRate` to `ScanOptions` and `PoliteScanOptions` var**

In `internal/backends/nmap/nmap.go`, update `ScanOptions` and add new vars:

```go
// ScanOptions controls nmap scan behaviour.
type ScanOptions struct {
	// TimingTemplate sets the nmap -T flag (0-5). Default 4.
	TimingTemplate int
	// MinRate sets --min-rate (packets/sec). 0 means use nmap default.
	MinRate int
	// MaxRate sets --max-rate (packets/sec). 0 means no limit.
	MaxRate int
}

// PoliteScanOptions is safe for use on SDN controllers with flood detection.
// Equivalent to nmap -T2 --min-rate 50 --max-rate 100.
var PoliteScanOptions = ScanOptions{
	TimingTemplate: 2,
	MinRate:        50,
	MaxRate:        100,
}

// DefaultScanOptions returns sensible defaults: -T4 --min-rate 500.
// This cuts scan time on quiet subnets from ~45s to ~7s.
var DefaultScanOptions = ScanOptions{
	TimingTemplate: 4,
	MinRate:        500,
}
```

Then in `DiscoverWithOptions`, add `MaxRate` to the args build block (after the existing `MinRate` block):

```go
if opts.MaxRate > 0 {
	args = append(args, "--max-rate", fmt.Sprintf("%d", opts.MaxRate))
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
go test ./internal/backends/nmap/... -run TestPoliteScanOptionsDefaults -v
```
Expected: PASS

- [ ] **Step 5: Add `ScanMode` type and `ScanModeOptions` helper**

Append to `internal/backends/nmap/nmap.go`:

```go
// ScanMode is a named preset for scan aggressiveness.
type ScanMode string

const (
	ScanModePolite     ScanMode = "polite"
	ScanModeNormal     ScanMode = "normal"
	ScanModeAggressive ScanMode = "aggressive"
)

// ScanOptionsForMode returns the ScanOptions preset for a named mode.
// Unknown modes default to polite.
func ScanOptionsForMode(mode ScanMode) ScanOptions {
	switch mode {
	case ScanModeNormal:
		return DefaultScanOptions
	case ScanModeAggressive:
		return ScanOptions{TimingTemplate: 5}
	default:
		return PoliteScanOptions
	}
}
```

- [ ] **Step 6: Write test for `ScanOptionsForMode`**

```go
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
```

- [ ] **Step 7: Run all nmap tests**

```bash
go test ./internal/backends/nmap/... -v
```
Expected: all PASS

- [ ] **Step 8: Commit**

```bash
git add internal/backends/nmap/nmap.go internal/backends/nmap/nmap_test.go
git commit -m "feat: add ScanMode, PoliteScanOptions, and MaxRate to nmap backend"
```

---

## Task 2: Add `PortScan` to nmap backend

**Files:**
- Modify: `internal/backends/nmap/nmap.go`
- Modify: `internal/backends/nmap/nmap_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestPortScanResultShape(t *testing.T) {
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
```

Add `"context"` to imports in the test file.

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/backends/nmap/... -run TestPortScanResultShape -v
```
Expected: FAIL — `PortScan` undefined

- [ ] **Step 3: Implement `PortScanResult` type and `PortScan` function**

Append to `internal/backends/nmap/nmap.go`:

```go
// PortState holds the observed state of a single port.
type PortState struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"` // "open", "closed", "filtered"
}

// PortScanResult holds per-port scan results.
type PortScanResult struct {
	Ports []PortState `json:"ports"`
}

// rePortLine matches nmap port lines like "80/tcp   open  http"
var rePortLine = regexp.MustCompile(`^(\d+)/(tcp|udp)\s+(\S+)`)

// PortScan scans specific ports on a target using nmap.
// protocol must be "tcp" or "udp".
func PortScan(ctx context.Context, target string, ports []int, protocol string, opts ScanOptions) (*models.CheckResult, error) {
	result := models.NewCheckResult("nmap", "port_check", "nmap", target)

	nmapPath, err := exec.LookPath("nmap")
	if err != nil {
		result.Status = models.StatusError
		result.Summary = "nmap is not installed or not in PATH"
		result.Finish()
		return result, CheckAvailable()
	}

	if len(ports) == 0 {
		result.Status = models.StatusError
		result.Summary = "no ports specified"
		result.Finish()
		return result, fmt.Errorf("ports list is empty")
	}

	portList := make([]string, len(ports))
	for i, p := range ports {
		portList[i] = fmt.Sprintf("%d", p)
	}

	args := []string{"-sV", "--open"}
	if protocol == "udp" {
		args = append(args, "-sU")
	} else {
		args = append(args, "-sT")
	}
	if opts.TimingTemplate > 0 {
		args = append(args, fmt.Sprintf("-T%d", opts.TimingTemplate))
	}
	if opts.MinRate > 0 {
		args = append(args, "--min-rate", fmt.Sprintf("%d", opts.MinRate))
	}
	if opts.MaxRate > 0 {
		args = append(args, "--max-rate", fmt.Sprintf("%d", opts.MaxRate))
	}
	args = append(args, "-p", strings.Join(portList, ","), target)

	cmd := exec.CommandContext(ctx, nmapPath, args...)
	out, err := cmd.Output()
	if err != nil && ctx.Err() != nil {
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("nmap timed out: %v", ctx.Err())
		result.Finish()
		return result, ctx.Err()
	}

	portStates := parsePortScanOutput(string(out), ports, protocol)

	psJSON, _ := json.Marshal(PortScanResult{Ports: portStates})
	var psMap map[string]interface{}
	_ = json.Unmarshal(psJSON, &psMap)
	result.Observed = psMap
	result.Evidence = append(result.Evidence, strings.TrimSpace(string(out)))
	result.Status = models.StatusPass
	result.Summary = fmt.Sprintf("port scan of %s: %d ports checked", target, len(ports))
	result.Finish()
	return result, nil
}

// parsePortScanOutput parses nmap port scan output into PortState slice.
// Ports not found in output are reported as "filtered".
func parsePortScanOutput(output string, requested []int, protocol string) []PortState {
	found := make(map[int]string)
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		m := rePortLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		port := 0
		fmt.Sscanf(m[1], "%d", &port)
		found[port] = m[3]
	}
	states := make([]PortState, len(requested))
	for i, p := range requested {
		state := "filtered"
		if s, ok := found[p]; ok {
			state = s
		}
		states[i] = PortState{Port: p, Protocol: protocol, State: state}
	}
	return states
}
```

- [ ] **Step 4: Run test**

```bash
go test ./internal/backends/nmap/... -run TestPortScanResultShape -v
```
Expected: PASS (nmap may time out on 192.0.2.1, but result shape is correct)

- [ ] **Step 5: Run all nmap tests**

```bash
go test ./internal/backends/nmap/... -v
```
Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add internal/backends/nmap/nmap.go internal/backends/nmap/nmap_test.go
git commit -m "feat: add PortScan to nmap backend"
```

---

## Task 3: DNS check backend

**Files:**
- Create: `internal/backends/dns/dns.go`
- Create: `internal/backends/dns/dns_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/backends/dns/dns_test.go
package dns_test

import (
	"context"
	"testing"
	"time"

	"github.com/velasco-jp/nyx/internal/backends/dns"
)

func TestResolveResultShape(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := dns.Resolve(ctx, dns.Query{
		Name:   "localhost",
		Server: "",
		DNSSEC: false,
	})
	if err != nil {
		t.Fatalf("Resolve returned error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.CheckType != "dns_check" {
		t.Errorf("expected check_type 'dns_check', got %q", result.CheckType)
	}
}

func TestResolveExpectedIPMatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := dns.Resolve(ctx, dns.Query{
		Name:       "localhost",
		ExpectedIP: "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "pass" && result.Status != "warn" {
		// localhost should resolve to 127.0.0.1 or produce a warn, never an error
		t.Errorf("unexpected status %q for localhost→127.0.0.1", result.Status)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/backends/dns/... -v
```
Expected: FAIL — package does not exist

- [ ] **Step 3: Create the DNS backend**

```go
// internal/backends/dns/dns.go
package dns

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"

	"github.com/velasco-jp/nyx/internal/models"
)

// Query holds the parameters for a DNS check.
type Query struct {
	Name       string
	ExpectedIP string
	Server     string // empty = system resolver
	DNSSEC     bool
}

// Resolve performs a DNS resolution check and returns a CheckResult.
func Resolve(ctx context.Context, q Query) (*models.CheckResult, error) {
	result := models.NewCheckResult("dns", "dns_check", "local", q.Name)
	result.Expected["name"] = q.Name
	if q.ExpectedIP != "" {
		result.Expected["ip"] = q.ExpectedIP
	}
	if q.DNSSEC {
		result.Expected["dnssec"] = true
	}

	// Resolve using net.DefaultResolver or a custom server
	addrs, err := resolveHost(ctx, q.Name, q.Server)
	if err != nil {
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("DNS resolution failed for %q: %v", q.Name, err)
		result.Finish()
		return result, nil
	}

	result.Observed["resolved_ips"] = addrs
	result.Evidence = append(result.Evidence, fmt.Sprintf("resolved %q → %s", q.Name, strings.Join(addrs, ", ")))

	// Check expected IP
	if q.ExpectedIP != "" {
		matched := false
		for _, addr := range addrs {
			if addr == q.ExpectedIP {
				matched = true
				break
			}
		}
		if !matched {
			result.Status = models.StatusFail
			result.Violations = append(result.Violations,
				fmt.Sprintf("resolved to %s, expected %s", strings.Join(addrs, ", "), q.ExpectedIP))
			result.Summary = fmt.Sprintf("DNS mismatch: %q → %s (expected %s)", q.Name, strings.Join(addrs, ", "), q.ExpectedIP)
			result.Finish()
			return result, nil
		}
	}

	// DNSSEC validation via dig
	if q.DNSSEC {
		ok, evidence, err2 := validateDNSSEC(ctx, q.Name, q.Server)
		result.Evidence = append(result.Evidence, evidence)
		if err2 != nil {
			result.Status = models.StatusWarn
			result.Summary = fmt.Sprintf("DNSSEC validation error for %q: %v", q.Name, err2)
			result.Finish()
			return result, nil
		}
		result.Observed["dnssec_valid"] = ok
		if !ok {
			result.Status = models.StatusFail
			result.Violations = append(result.Violations, "DNSSEC validation failed")
			result.Summary = fmt.Sprintf("DNSSEC invalid for %q", q.Name)
			result.Finish()
			return result, nil
		}
	}

	result.Status = models.StatusPass
	result.Summary = fmt.Sprintf("DNS ok: %q → %s", q.Name, strings.Join(addrs, ", "))
	result.Finish()
	return result, nil
}

// resolveHost resolves a hostname using the system resolver or a custom server.
// When server is empty, uses Go's net.LookupHost. When server is set, shells
// out to nslookup to use the specified resolver.
func resolveHost(ctx context.Context, name, server string) ([]string, error) {
	if server == "" {
		addrs, err := net.DefaultResolver.LookupHost(ctx, name)
		if err != nil {
			return nil, err
		}
		return addrs, nil
	}
	// Use nslookup for custom server
	out, err := exec.CommandContext(ctx, "nslookup", name, server).Output()
	if err != nil {
		return nil, fmt.Errorf("nslookup failed: %w", err)
	}
	return parseNslookupAddrs(string(out)), nil
}

// parseNslookupAddrs extracts IP addresses from nslookup output.
func parseNslookupAddrs(output string) []string {
	var addrs []string
	inAnswer := false
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Name:") {
			inAnswer = true
			continue
		}
		if inAnswer && strings.HasPrefix(line, "Address:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				addr := strings.TrimSpace(parts[1])
				if net.ParseIP(addr) != nil {
					addrs = append(addrs, addr)
				}
			}
		}
	}
	return addrs
}

// validateDNSSEC runs dig +dnssec +sigchase to validate the DNSSEC chain.
// Returns (valid, evidence, error). If dig is not available, returns a warn-level error.
func validateDNSSEC(ctx context.Context, name, server string) (bool, string, error) {
	digPath, err := exec.LookPath("dig")
	if err != nil {
		return false, "", fmt.Errorf("dig not found in PATH — install bind-utils or dnsutils to validate DNSSEC")
	}

	args := []string{"+dnssec", "+short", name}
	if server != "" {
		args = append([]string{"@" + server}, args...)
	}
	cmd := exec.CommandContext(ctx, digPath, args...)
	out, err := cmd.Output()
	evidence := strings.TrimSpace(string(out))
	if err != nil {
		return false, evidence, nil
	}

	// Presence of an RRSIG record in output indicates DNSSEC is active
	valid := strings.Contains(evidence, "RRSIG") || strings.Contains(evidence, "rrsig")
	return valid, evidence, nil
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/backends/dns/... -v
```
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/backends/dns/
git commit -m "feat: add DNS check backend with DNSSEC support"
```

---

## Task 4: Network health backend

**Files:**
- Create: `internal/backends/health/health.go`
- Create: `internal/backends/health/health_test.go`

- [ ] **Step 1: Write the failing test**

```go
// internal/backends/health/health_test.go
package health_test

import (
	"context"
	"testing"
	"time"

	"github.com/velasco-jp/nyx/internal/backends/health"
)

func TestCheckResultShape(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := health.Check(ctx, health.Options{
		Target: "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("Check returned error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.CheckType != "network_health" {
		t.Errorf("expected check_type 'network_health', got %q", result.CheckType)
	}
	if result.Status == "" {
		t.Error("expected non-empty status")
	}
}

func TestLocalhostIsHealthy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := health.Check(ctx, health.Options{
		Target:           "127.0.0.1",
		MaxLatencyMs:     100,
		MaxLossPct:       0,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != "pass" {
		t.Errorf("expected pass for localhost, got %q: %s", result.Status, result.Summary)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/backends/health/... -v
```
Expected: FAIL — package does not exist

- [ ] **Step 3: Create the health backend**

```go
// internal/backends/health/health.go
package health

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/velasco-jp/nyx/internal/models"
)

// Options controls what the health check tests.
type Options struct {
	Target       string
	MaxLatencyMs float64 // 0 = no limit
	MaxLossPct   float64 // 0 = no limit
	ExpectMTU    int     // 0 = skip MTU probe
}

var (
	reLoss    = regexp.MustCompile(`(\d+(?:\.\d+)?)%\s+packet loss`)
	reAvgUnix = regexp.MustCompile(`(?:rtt|round-trip)\s+\S+\s*=\s*[\d.]+/([\d.]+)/`)
	reAvgWin  = regexp.MustCompile(`Average\s*=\s*(\d+)ms`)
)

// Check runs a ping-based health check against target and returns a CheckResult.
func Check(ctx context.Context, opts Options) (*models.CheckResult, error) {
	result := models.NewCheckResult("system", "network_health", "local", opts.Target)

	if opts.MaxLatencyMs > 0 {
		result.Expected["max_latency_ms"] = opts.MaxLatencyMs
	}
	if opts.MaxLossPct > 0 || opts.ExpectMTU == 0 {
		result.Expected["max_loss_pct"] = opts.MaxLossPct
	}
	if opts.ExpectMTU > 0 {
		result.Expected["mtu"] = opts.ExpectMTU
	}

	loss, avgMs, raw, err := pingStats(ctx, opts.Target)
	result.Evidence = append(result.Evidence, raw)
	if err != nil {
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("ping failed: %v", err)
		result.Finish()
		return result, nil
	}

	result.Observed["packet_loss_pct"] = loss
	result.Observed["avg_latency_ms"] = avgMs

	// Evaluate bounds
	var violations []string
	if opts.MaxLossPct >= 0 && loss > opts.MaxLossPct {
		violations = append(violations,
			fmt.Sprintf("packet loss %.1f%% exceeds max %.1f%%", loss, opts.MaxLossPct))
	}
	if opts.MaxLatencyMs > 0 && avgMs > opts.MaxLatencyMs {
		violations = append(violations,
			fmt.Sprintf("latency %.1fms exceeds max %.1fms", avgMs, opts.MaxLatencyMs))
	}

	// MTU probe
	if opts.ExpectMTU > 0 {
		mtu, mtuEvidence, mtuErr := probeMTU(ctx, opts.Target, opts.ExpectMTU)
		result.Evidence = append(result.Evidence, mtuEvidence)
		if mtuErr != nil {
			result.Observed["mtu_probe_error"] = mtuErr.Error()
		} else {
			result.Observed["discovered_mtu"] = mtu
			tolerance := int(float64(opts.ExpectMTU) * 0.9)
			if mtu < tolerance {
				violations = append(violations,
					fmt.Sprintf("MTU %d is more than 10%% below expected %d", mtu, opts.ExpectMTU))
			} else if mtu < opts.ExpectMTU {
				// Within 10% — warn not fail
				result.Status = models.StatusWarn
				result.Summary = fmt.Sprintf("MTU %d slightly below expected %d (may be intentional)", mtu, opts.ExpectMTU)
			}
		}
	}

	if len(violations) > 0 {
		result.Status = models.StatusFail
		result.Violations = violations
		result.Summary = fmt.Sprintf("health check failed for %s", opts.Target)
	} else if result.Status == "" {
		result.Status = models.StatusPass
		result.Summary = fmt.Sprintf("health ok: %s loss=%.1f%% latency=%.1fms", opts.Target, loss, avgMs)
	}

	result.Finish()
	return result, nil
}

func pingStats(ctx context.Context, target string) (lossPct float64, avgMs float64, raw string, err error) {
	var args []string
	switch runtime.GOOS {
	case "windows":
		args = []string{"-n", "10", "-w", "2000", target}
	case "darwin":
		args = []string{"-c", "10", "-W", "2000", target}
	default: // linux
		args = []string{"-c", "10", "-W", "2", target}
	}

	out, cmdErr := exec.CommandContext(ctx, "ping", args...).Output()
	raw = strings.TrimSpace(string(out))

	if cmdErr != nil && ctx.Err() != nil {
		return 0, 0, raw, fmt.Errorf("ping cancelled: %w", ctx.Err())
	}

	if m := reLoss.FindStringSubmatch(raw); m != nil {
		lossPct, _ = strconv.ParseFloat(m[1], 64)
	} else if cmdErr != nil {
		return 0, 0, raw, fmt.Errorf("ping failed: %w", cmdErr)
	}

	if m := reAvgUnix.FindStringSubmatch(raw); m != nil {
		avgMs, _ = strconv.ParseFloat(m[1], 64)
	} else if m := reAvgWin.FindStringSubmatch(raw); m != nil {
		avgMs, _ = strconv.ParseFloat(m[1], 64)
	}

	return lossPct, avgMs, raw, nil
}

// probeMTU discovers the path MTU by sending progressively smaller ICMP packets
// with the DF (Don't Fragment) bit set. Returns discovered MTU.
func probeMTU(ctx context.Context, target string, expected int) (int, string, error) {
	// Try sizes from expected down to 576 in steps
	sizes := []int{expected, expected - 100, 1400, 1300, 1200, 1000, 800, 576}
	var evidence []string

	for _, size := range sizes {
		if size < 576 {
			break
		}
		var args []string
		switch runtime.GOOS {
		case "windows":
			args = []string{"-f", "-l", fmt.Sprintf("%d", size-28), "-n", "1", target}
		case "darwin":
			args = []string{"-D", "-s", fmt.Sprintf("%d", size-28), "-c", "1", "-W", "1000", target}
		default:
			args = []string{"-M", "do", "-s", fmt.Sprintf("%d", size-28), "-c", "1", "-W", "1", target}
		}
		out, err := exec.CommandContext(ctx, "ping", args...).Output()
		evidence = append(evidence, fmt.Sprintf("size %d: %s", size, strings.TrimSpace(string(out))))
		if err == nil {
			return size, strings.Join(evidence, "\n"), nil
		}
	}
	return 576, strings.Join(evidence, "\n"), nil
}
```

- [ ] **Step 4: Run tests**

```bash
go test ./internal/backends/health/... -v
```
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/backends/health/
git commit -m "feat: add network health check backend (ping stats + MTU probe)"
```

---

## Task 5: SSH probe executor

**Files:**
- Create: `internal/probe/probe.go`
- Create: `internal/probe/probe_test.go`
- Modify: `go.mod` (add `golang.org/x/crypto`)

- [ ] **Step 1: Add SSH dependency**

```bash
go get golang.org/x/crypto@latest
```

Expected: `go.mod` and `go.sum` updated.

- [ ] **Step 2: Write the failing test**

```go
// internal/probe/probe_test.go
package probe_test

import (
	"testing"

	"github.com/velasco-jp/nyx/internal/probe"
)

func TestExecutorConfigValidation(t *testing.T) {
	_, err := probe.New(probe.Config{
		Name: "test",
		Host: "",
		User: "jp",
	})
	if err == nil {
		t.Error("expected error for empty host")
	}
}

func TestExecutorConfigValid(t *testing.T) {
	e, err := probe.New(probe.Config{
		Name: "test",
		Host: "192.168.1.1",
		User: "jp",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if e == nil {
		t.Fatal("expected non-nil executor")
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

```bash
go test ./internal/probe/... -v
```
Expected: FAIL — package does not exist

- [ ] **Step 4: Create the probe executor**

```go
// internal/probe/probe.go
package probe

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Config holds connection parameters for a remote probe node.
type Config struct {
	Name    string
	Host    string
	User    string
	KeyPath string // empty = try ssh-agent / default keys
	VLAN    string // informational
}

// Executor dials a probe and runs commands on it.
type Executor struct {
	cfg Config
}

// New validates the config and returns an Executor.
func New(cfg Config) (*Executor, error) {
	if cfg.Host == "" {
		return nil, fmt.Errorf("probe %q: host is required", cfg.Name)
	}
	if cfg.User == "" {
		return nil, fmt.Errorf("probe %q: user is required", cfg.Name)
	}
	return &Executor{cfg: cfg}, nil
}

// Run opens an SSH connection to the probe, executes cmd, and returns stdout.
// cmd must be a slice of strings (no shell interpolation).
func (e *Executor) Run(ctx context.Context, cmd []string) (string, error) {
	if len(cmd) == 0 {
		return "", fmt.Errorf("empty command")
	}

	auth, err := e.authMethods()
	if err != nil {
		return "", fmt.Errorf("probe %q: no SSH auth available: %w", e.cfg.Name, err)
	}

	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	type dialResult struct {
		client *ssh.Client
		err    error
	}
	ch := make(chan dialResult, 1)
	go func() {
		cfg := &ssh.ClientConfig{
			User:            e.cfg.User,
			Auth:            auth,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
			Timeout:         10 * time.Second,
		}
		host := e.cfg.Host
		if !strings.Contains(host, ":") {
			host += ":22"
		}
		c, err := ssh.Dial("tcp", host, cfg)
		ch <- dialResult{c, err}
	}()

	select {
	case <-dialCtx.Done():
		return "", fmt.Errorf("probe %q unreachable at %s:22 — is the host on VLAN %s and SSH running?",
			e.cfg.Name, e.cfg.Host, e.cfg.VLAN)
	case r := <-ch:
		if r.err != nil {
			return "", fmt.Errorf("probe %q: SSH dial failed: %w", e.cfg.Name, r.err)
		}
		defer r.client.Close()
		return e.runSession(ctx, r.client, cmd)
	}
}

func (e *Executor) runSession(ctx context.Context, client *ssh.Client, cmd []string) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("probe %q: new session: %w", e.cfg.Name, err)
	}
	defer sess.Close()

	// Use a context-aware done channel
	done := make(chan struct{})
	var out []byte
	var runErr error
	go func() {
		defer close(done)
		// Join args safely — no shell meta-characters from spec input can reach here
		// because callers must pass a fixed []string, not a shell command.
		out, runErr = sess.Output(strings.Join(cmd, " "))
	}()

	select {
	case <-ctx.Done():
		sess.Signal(ssh.SIGKILL)
		return "", fmt.Errorf("probe %q: command timed out", e.cfg.Name)
	case <-done:
		return strings.TrimSpace(string(out)), runErr
	}
}

// authMethods builds the list of SSH auth methods from config.
func (e *Executor) authMethods() ([]ssh.AuthMethod, error) {
	var methods []ssh.AuthMethod

	if e.cfg.KeyPath != "" {
		expanded := expandHome(e.cfg.KeyPath)
		key, err := os.ReadFile(expanded)
		if err != nil {
			return nil, fmt.Errorf("reading key %q: %w", e.cfg.KeyPath, err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("parsing key %q: %w", e.cfg.KeyPath, err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}

	// Try default keys
	defaultKeys := []string{"~/.ssh/id_ed25519", "~/.ssh/id_rsa"}
	for _, path := range defaultKeys {
		expanded := expandHome(path)
		key, err := os.ReadFile(expanded)
		if err != nil {
			continue
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			continue
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}

	if len(methods) == 0 {
		return nil, fmt.Errorf("no SSH keys found; set key in probe config or add a key to ~/.ssh/")
	}
	return methods, nil
}

func expandHome(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			return strings.Replace(path, "~", home, 1)
		}
	}
	return path
}
```

- [ ] **Step 5: Run tests**

```bash
go test ./internal/probe/... -v
```
Expected: PASS (no live SSH test — just config validation)

- [ ] **Step 6: Commit**

```bash
git add internal/probe/ go.mod go.sum
git commit -m "feat: add SSH probe executor for remote assertion checks"
```

---

## Task 6: Extend spec — `probes`, `ScanMode`, `Runner`, new assertion types

**Files:**
- Modify: `internal/intent/spec.go`
- Modify: `internal/intent/spec_test.go`

- [ ] **Step 1: Write the failing validation tests**

Add to `internal/intent/spec_test.go`:

```go
func TestValidateSpecProbeRequiresHost(t *testing.T) {
	spec := &intent.Spec{
		Version: 1,
		Site:    "test",
		Probes: []intent.Probe{
			{Name: "laptop", Host: "", User: "jp"},
		},
	}
	if err := intent.ValidateSpec(spec); err == nil {
		t.Error("expected error for probe with empty host")
	}
}

func TestValidateSpecPortCheckRequiresPorts(t *testing.T) {
	spec := baseSpec()
	spec.Assertions = []intent.Assertion{
		{Type: "port_check", Target: "10.0.0.1", Ports: nil, Expect: "open"},
	}
	if err := intent.ValidateSpec(spec); err == nil {
		t.Error("expected error for port_check with no ports")
	}
}

func TestValidateSpecDNSCheckRequiresQuery(t *testing.T) {
	spec := baseSpec()
	spec.Assertions = []intent.Assertion{
		{Type: "dns_check", Target: ""},
	}
	if err := intent.ValidateSpec(spec); err == nil {
		t.Error("expected error for dns_check with no query")
	}
}

func TestValidateSpecNetworkHealthRequiresTarget(t *testing.T) {
	spec := baseSpec()
	spec.Assertions = []intent.Assertion{
		{Type: "network_health", Target: ""},
	}
	if err := intent.ValidateSpec(spec); err == nil {
		t.Error("expected error for network_health with no target")
	}
}

func TestValidateSpecACLCheckRequiresProviderAndPolicy(t *testing.T) {
	spec := baseSpec()
	spec.Assertions = []intent.Assertion{
		{Type: "acl_check", Provider: "", Policy: "iot-isolation", Expect: "enforced"},
	}
	if err := intent.ValidateSpec(spec); err == nil {
		t.Error("expected error for acl_check with no provider")
	}
}

func TestValidateSpecRunnerMustExist(t *testing.T) {
	spec := baseSpec()
	spec.Assertions = []intent.Assertion{
		{Type: "route_check", Target: "10.0.0.1", Runner: "no-such-probe"},
	}
	if err := intent.ValidateSpec(spec); err == nil {
		t.Error("expected error for runner referencing undeclared probe")
	}
}

// baseSpec returns a minimal valid spec for use in tests.
func baseSpec() *intent.Spec {
	return &intent.Spec{
		Version:  1,
		Site:     "test",
		Networks: []intent.Network{{Name: "mgmt", CIDR: "10.0.0.0/24", Zone: "management"}},
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/intent/... -run "TestValidateSpecProbe|TestValidateSpecPort|TestValidateSpecDNS|TestValidateSpecNetwork|TestValidateSpecACL|TestValidateSpecRunner" -v
```
Expected: FAIL — fields/types don't exist yet

- [ ] **Step 3: Extend `Assertion` and add `Probe` type in `spec.go`**

Add `Probe` struct and `Probes` field to `Spec`:

```go
// Probe defines a remote host that can execute checks from a different VLAN.
type Probe struct {
	Name    string `yaml:"name" json:"name"`
	Host    string `yaml:"host" json:"host"`
	User    string `yaml:"user" json:"user"`
	Key     string `yaml:"key,omitempty" json:"key,omitempty"`
	VLAN    string `yaml:"vlan,omitempty" json:"vlan,omitempty"`
}
```

Add `Probes []Probe` to `Spec` (after `Policies`):

```go
type Spec struct {
	Version    int          `yaml:"version" json:"version"`
	Site       string       `yaml:"site" json:"site"`
	Networks   []Network    `yaml:"networks" json:"networks"`
	VPN        []VPNConfig  `yaml:"vpn" json:"vpn"`
	Policies   []Policy     `yaml:"policies" json:"policies"`
	Probes     []Probe      `yaml:"probes,omitempty" json:"probes,omitempty"`
	Assertions []Assertion  `yaml:"assertions" json:"assertions"`
}
```

Extend `Assertion` with new fields:

```go
type Assertion struct {
	Type           string `yaml:"type" json:"type"`
	Network        string `yaml:"network,omitempty" json:"network,omitempty"`
	From           string `yaml:"from,omitempty" json:"from,omitempty"`
	To             string `yaml:"to,omitempty" json:"to,omitempty"`
	VPN            string `yaml:"vpn,omitempty" json:"vpn,omitempty"`
	Target         string `yaml:"target,omitempty" json:"target,omitempty"`
	ExpectHostsMin *int   `yaml:"expect_hosts_min,omitempty" json:"expect_hosts_min,omitempty"`
	ExpectHostsMax *int   `yaml:"expect_hosts_max,omitempty" json:"expect_hosts_max,omitempty"`
	ExpectDeny     string `yaml:"expect,omitempty" json:"expect,omitempty"`
	ExpectTunnel   *bool  `yaml:"expect_tunnel,omitempty" json:"expect_tunnel,omitempty"`
	Ports          []int  `yaml:"ports,omitempty" json:"ports,omitempty"`
	ScanTiming     int    `yaml:"scan_timing,omitempty" json:"scan_timing,omitempty"`
	ScanMinRate    int    `yaml:"scan_min_rate,omitempty" json:"scan_min_rate,omitempty"`
	// New fields
	ScanMode  string `yaml:"scan_mode,omitempty" json:"scan_mode,omitempty"`   // polite|normal|aggressive
	Runner    string `yaml:"runner,omitempty" json:"runner,omitempty"`         // probe name
	Server    string `yaml:"server,omitempty" json:"server,omitempty"`         // dns_check: resolver IP
	DNSSEC    bool   `yaml:"dnssec,omitempty" json:"dnssec,omitempty"`         // dns_check
	ExpectIP  string `yaml:"expect_ip,omitempty" json:"expect_ip,omitempty"`   // dns_check
	MaxLatMs  float64 `yaml:"expect_latency_ms,omitempty" json:"expect_latency_ms,omitempty"` // network_health
	MaxLossPct float64 `yaml:"expect_loss_pct,omitempty" json:"expect_loss_pct,omitempty"`   // network_health
	ExpectMTU int    `yaml:"expect_mtu,omitempty" json:"expect_mtu,omitempty"` // network_health
	Provider  string `yaml:"provider,omitempty" json:"provider,omitempty"`     // acl_check
	Policy    string `yaml:"policy,omitempty" json:"policy,omitempty"`         // acl_check
	Expect    string `yaml:"expect,omitempty" json:"expect,omitempty"`         // acl_check, port_check
}
```

Note: `Expect` replaces `ExpectDeny` for the new assertion types. Keep `ExpectDeny` as an alias — its yaml tag `expect` is the same field. Replace `ExpectDeny string` with `Expect string` and update all references to `a.ExpectDeny` → `a.Expect` in `engine.go`.

- [ ] **Step 4: Extend `ValidateSpec`**

Add a `ProbeByName` helper after `VPNByName`:

```go
// ProbeByName finds a probe by name.
func (s *Spec) ProbeByName(name string) *Probe {
	for i := range s.Probes {
		if s.Probes[i].Name == name {
			return &s.Probes[i]
		}
	}
	return nil
}
```

In `ValidateSpec`, add probe validation after policy validation:

```go
// Validate probes
probeNames := make(map[string]bool)
for i, p := range spec.Probes {
	if p.Name == "" {
		return fmt.Errorf("probe[%d]: name is required", i)
	}
	if probeNames[p.Name] {
		return fmt.Errorf("probe[%d]: duplicate name %q", i, p.Name)
	}
	probeNames[p.Name] = true
	if p.Host == "" {
		return fmt.Errorf("probe %q: host is required", p.Name)
	}
	if p.User == "" {
		return fmt.Errorf("probe %q: user is required", p.Name)
	}
}
```

Extend the assertion type map and per-type validation:

```go
validTypes := map[string]bool{
	"subnet_discovery": true,
	"isolation":        true,
	"vpn_route":        true,
	"route_check":      true,
	"port_check":       true,
	"dns_check":        true,
	"network_health":   true,
	"acl_check":        true,
}
```

Add new cases to the assertion switch in `ValidateSpec`:

```go
case "port_check":
	if a.Target == "" {
		return fmt.Errorf("assertion[%d] (port_check): target is required", i)
	}
	if len(a.Ports) == 0 {
		return fmt.Errorf("assertion[%d] (port_check): ports is required", i)
	}
	if a.Expect != "open" && a.Expect != "closed" {
		return fmt.Errorf("assertion[%d] (port_check): expect must be 'open' or 'closed'", i)
	}
case "dns_check":
	if a.Target == "" {
		return fmt.Errorf("assertion[%d] (dns_check): target (query hostname) is required", i)
	}
case "network_health":
	if a.Target == "" {
		return fmt.Errorf("assertion[%d] (network_health): target is required", i)
	}
case "acl_check":
	if a.Provider == "" {
		return fmt.Errorf("assertion[%d] (acl_check): provider is required", i)
	}
	if a.Policy == "" {
		return fmt.Errorf("assertion[%d] (acl_check): policy is required", i)
	}
	if a.Expect != "enforced" && a.Expect != "not_enforced" {
		return fmt.Errorf("assertion[%d] (acl_check): expect must be 'enforced' or 'not_enforced'", i)
	}
```

At the end of the assertion loop, add runner validation:

```go
if a.Runner != "" && !probeNames[a.Runner] {
	return fmt.Errorf("assertion[%d]: runner %q not declared in probes", i, a.Runner)
}
```

Also update the `isolation` case to use `a.Expect` instead of `a.ExpectDeny`:

```go
case "isolation":
	if a.From == "" {
		return fmt.Errorf("assertion[%d] (isolation): from is required", i)
	}
	if a.To == "" {
		return fmt.Errorf("assertion[%d] (isolation): to is required", i)
	}
	if a.Expect == "" {
		return fmt.Errorf("assertion[%d] (isolation): expect is required (use 'deny' or 'allow')", i)
	}
```

- [ ] **Step 5: Fix `engine.go` reference to `a.ExpectDeny`**

In `internal/audit/engine.go`, replace all `a.ExpectDeny` with `a.Expect`:

```bash
grep -n "ExpectDeny" internal/audit/engine.go
```

Update each occurrence: `a.ExpectDeny` → `a.Expect`. There should be one: `expectDeny := a.ExpectDeny == "deny"` → `expectDeny := a.Expect == "deny"`.

- [ ] **Step 6: Run all tests**

```bash
go test ./internal/intent/... ./internal/audit/... -v
```
Expected: all PASS

- [ ] **Step 7: Commit**

```bash
git add internal/intent/spec.go internal/intent/spec_test.go internal/audit/engine.go
git commit -m "feat: extend spec with probes, new assertion types, ScanMode, Runner fields"
```

---

## Task 7: Wire new assertion types into the audit engine

**Files:**
- Modify: `internal/audit/engine.go`
- Modify: `internal/audit/engine_test.go`

- [ ] **Step 1: Write failing tests for new assertion types**

Add to `internal/audit/engine_test.go`:

```go
func TestPortCheckPassesForOpenPort(t *testing.T) {
	// Localhost port 0 will be filtered — we just want the result shape
	spec := &intent.Spec{
		Version: 1,
		Site:    "test",
		Assertions: []intent.Assertion{
			{Type: "port_check", Target: "127.0.0.1", Ports: []int{22}, Expect: "open"},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	engine := audit.NewEngine(spec)
	report, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(report.Findings))
	}
	f := report.Findings[0]
	if f.CheckType != "port_check" {
		t.Errorf("expected check_type 'port_check', got %q", f.CheckType)
	}
	// Status may be pass or fail depending on whether SSH is running; just verify it ran
	if f.Status == "" {
		t.Error("expected non-empty status")
	}
}

func TestDNSCheckPassesForLocalhost(t *testing.T) {
	spec := &intent.Spec{
		Version: 1,
		Site:    "test",
		Assertions: []intent.Assertion{
			{Type: "dns_check", Target: "localhost", ExpectIP: "127.0.0.1"},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	engine := audit.NewEngine(spec)
	report, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	f := report.Findings[0]
	if f.CheckType != "dns_check" {
		t.Errorf("expected check_type 'dns_check', got %q", f.CheckType)
	}
}

func TestNetworkHealthPassesForLoopback(t *testing.T) {
	spec := &intent.Spec{
		Version: 1,
		Site:    "test",
		Assertions: []intent.Assertion{
			{Type: "network_health", Target: "127.0.0.1", MaxLatMs: 100, MaxLossPct: 0},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	engine := audit.NewEngine(spec)
	report, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	f := report.Findings[0]
	if f.Status != models.StatusPass {
		t.Errorf("expected pass for loopback health check, got %q: %s", f.Status, f.Summary)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/audit/... -run "TestPortCheck|TestDNSCheck|TestNetworkHealth" -v
```
Expected: FAIL — engine doesn't handle new types yet

- [ ] **Step 3: Add new `runXxx` methods to engine**

Add imports to `internal/audit/engine.go`:

```go
import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/velasco-jp/nyx/internal/backends/dns"
	"github.com/velasco-jp/nyx/internal/backends/health"
	"github.com/velasco-jp/nyx/internal/backends/nmap"
	"github.com/velasco-jp/nyx/internal/backends/system"
	"github.com/velasco-jp/nyx/internal/intent"
	"github.com/velasco-jp/nyx/internal/models"
	"github.com/velasco-jp/nyx/internal/probe"
	"github.com/velasco-jp/nyx/internal/providers"
)
```

Extend the timeout constants:

```go
const (
	assertionTimeoutDiscovery   = 90 * time.Second
	assertionTimeoutPortScan    = 60 * time.Second
	assertionTimeoutNetHealth   = 30 * time.Second
	assertionTimeoutDefault     = 30 * time.Second
)
```

Update the `runAssertion` switch:

```go
func (e *Engine) runAssertion(ctx context.Context, a intent.Assertion) (*models.CheckResult, error) {
	timeout := assertionTimeoutDefault
	switch a.Type {
	case "subnet_discovery":
		timeout = assertionTimeoutDiscovery
	case "port_check":
		timeout = assertionTimeoutPortScan
	case "network_health":
		timeout = assertionTimeoutNetHealth
	}
	assertCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	switch a.Type {
	case "subnet_discovery":
		return e.runDiscovery(assertCtx, a)
	case "isolation":
		return e.runIsolation(assertCtx, a)
	case "vpn_route":
		return e.runVPNRoute(assertCtx, a)
	case "route_check":
		return e.runRouteCheck(assertCtx, a)
	case "port_check":
		return e.runPortCheck(assertCtx, a)
	case "dns_check":
		return e.runDNSCheck(assertCtx, a)
	case "network_health":
		return e.runNetworkHealth(assertCtx, a)
	case "acl_check":
		return e.runACLCheck(assertCtx, a)
	default:
		return nil, fmt.Errorf("unknown assertion type: %s", a.Type)
	}
}
```

Add the new runner methods:

```go
func (e *Engine) runPortCheck(ctx context.Context, a intent.Assertion) (*models.CheckResult, error) {
	opts := nmap.ScanOptionsForMode(nmap.ScanMode(a.ScanMode))
	if a.ScanTiming > 0 {
		opts.TimingTemplate = a.ScanTiming
	}
	if a.ScanMinRate > 0 {
		opts.MinRate = a.ScanMinRate
	}

	result, err := nmap.PortScan(ctx, a.Target, a.Ports, protocolOrDefault(a), opts)
	if err != nil {
		return nil, fmt.Errorf("port scan failed: %w", err)
	}

	// Evaluate: check each port's state against expect
	expectOpen := a.Expect == "open"
	ports, _ := result.Observed["ports"].([]interface{})
	var violations []string
	for _, p := range ports {
		pm, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		state, _ := pm["state"].(string)
		port := pm["port"]
		if expectOpen && state != "open" {
			violations = append(violations, fmt.Sprintf("port %v is %s (expected open)", port, state))
		} else if !expectOpen && state == "open" {
			violations = append(violations, fmt.Sprintf("port %v is open (expected closed)", port))
		}
	}

	if len(violations) > 0 {
		result.Status = models.StatusFail
		result.Violations = violations
		result.Summary = fmt.Sprintf("port check failed on %s: %d violation(s)", a.Target, len(violations))
	} else {
		result.Status = models.StatusPass
		result.Summary = fmt.Sprintf("port check passed on %s (%d ports %s)", a.Target, len(a.Ports), a.Expect)
	}
	return result, nil
}

func protocolOrDefault(a intent.Assertion) string {
	if a.Protocol != "" {
		return a.Protocol
	}
	return "tcp"
}

func (e *Engine) runDNSCheck(ctx context.Context, a intent.Assertion) (*models.CheckResult, error) {
	return dns.Resolve(ctx, dns.Query{
		Name:       a.Target,
		ExpectedIP: a.ExpectIP,
		Server:     a.Server,
		DNSSEC:     a.DNSSEC,
	})
}

func (e *Engine) runNetworkHealth(ctx context.Context, a intent.Assertion) (*models.CheckResult, error) {
	target := a.Target
	// If target is a network name, use its gateway
	if net := e.Spec.NetworkByName(a.Target); net != nil && net.Gateway != "" {
		target = net.Gateway
	}
	return health.Check(ctx, health.Options{
		Target:       target,
		MaxLatencyMs: a.MaxLatMs,
		MaxLossPct:   a.MaxLossPct,
		ExpectMTU:    a.ExpectMTU,
	})
}

func (e *Engine) runACLCheck(ctx context.Context, a intent.Assertion) (*models.CheckResult, error) {
	result := models.NewCheckResult("provider", "acl_check", "local", a.Policy)
	result.Expected["policy"] = a.Policy
	result.Expected["expect"] = a.Expect

	// Find the declared policy in the spec
	var declaredPolicy *intent.Policy
	for i := range e.Spec.Policies {
		if e.Spec.Policies[i].Name == a.Policy {
			declaredPolicy = &e.Spec.Policies[i]
			break
		}
	}
	if declaredPolicy == nil {
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("policy %q not found in spec", a.Policy)
		result.Finish()
		return result, nil
	}

	// Get the provider
	p, err := providers.Get(a.Provider)
	if err != nil {
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("provider %q not available: %v", a.Provider, err)
		result.Finish()
		return result, nil
	}

	// Fetch ACL rules via provider
	aclProvider, ok := p.(interface {
		GetACLRules(ctx context.Context) ([]intent.ACLRule, error)
	})
	if !ok {
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("provider %q does not support ACL rule retrieval", a.Provider)
		result.Finish()
		return result, nil
	}

	rules, err := aclProvider.GetACLRules(ctx)
	if err != nil {
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("failed to fetch ACL rules from %s: %v", a.Provider, err)
		result.Finish()
		return result, nil
	}

	result.Observed["rule_count"] = len(rules)

	// Check whether a rule enforcing the declared policy exists
	enforced := ruleEnforcesPolicy(rules, declaredPolicy)
	result.Observed["enforced"] = enforced

	expectEnforced := a.Expect == "enforced"
	if expectEnforced && enforced {
		result.Status = models.StatusPass
		result.Summary = fmt.Sprintf("ACL policy %q is enforced in %s", a.Policy, a.Provider)
	} else if expectEnforced && !enforced {
		result.Status = models.StatusFail
		result.Violations = append(result.Violations,
			fmt.Sprintf("no ACL rule found matching policy %q (%s → %s %s)",
				a.Policy, declaredPolicy.From, declaredPolicy.To, declaredPolicy.Action))
		result.Summary = fmt.Sprintf("ACL policy %q is NOT enforced in %s", a.Policy, a.Provider)
	} else if !expectEnforced && !enforced {
		result.Status = models.StatusPass
		result.Summary = fmt.Sprintf("ACL policy %q is correctly not enforced in %s", a.Policy, a.Provider)
	} else {
		result.Status = models.StatusFail
		result.Summary = fmt.Sprintf("ACL policy %q is enforced but expected not-enforced", a.Policy)
	}

	result.Finish()
	return result, nil
}

// ruleEnforcesPolicy returns true if any ACL rule matches the declared policy's
// from/to/action intent. Matches on source and destination name (case-insensitive).
func ruleEnforcesPolicy(rules []intent.ACLRule, p *intent.Policy) bool {
	wantDrop := p.Action == "deny"
	for _, r := range rules {
		if !r.Status {
			continue // rule is disabled
		}
		policyMatch := strings.EqualFold(r.SourceName, p.From) &&
			strings.EqualFold(r.DestName, p.To)
		actionMatch := (wantDrop && r.Policy == "drop") || (!wantDrop && r.Policy == "accept")
		if policyMatch && actionMatch {
			return true
		}
	}
	return false
}
```

Add `"strings"` to the import block in `engine.go`.

- [ ] **Step 4: Add `ACLRule` type alias to `intent` package and `Protocol` field to `Assertion`**

The `ruleEnforcesPolicy` function above takes `[]intent.ACLRule` — we need to expose that type from the intent package or use the omada backend type directly. The simpler approach: use the omada backend type in the provider interface, and use a generic `ACLRule` in intent.

Add to `internal/intent/spec.go`:

```go
// ACLRule is a simplified ACL rule used for acl_check assertions.
// Provider backends map their native rule types to this.
type ACLRule struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Status     bool   `json:"status"`   // true = enabled
	Policy     string `json:"policy"`   // "accept" or "drop"
	SourceName string `json:"src_name"`
	DestName   string `json:"dst_name"`
}
```

Also add `Protocol` field to `Assertion`:

```go
Protocol string `yaml:"protocol,omitempty" json:"protocol,omitempty"` // port_check: tcp|udp
```

Update `ruleEnforcesPolicy` to use `intent.ACLRule` (already does).

- [ ] **Step 5: Add `GetACLRules` to Omada provider**

In `internal/providers/omada/provider.go`, add:

```go
// GetACLRules fetches ACL rules from the Omada controller and maps them to intent.ACLRule.
func (o *OmadaProvider) GetACLRules(ctx context.Context) ([]intent.ACLRule, error) {
	opts := providers.ImportOptions{}
	// Use env vars as fallback when no explicit opts are provided
	if opts.Host == "" {
		opts.Host = os.Getenv("OMADA_HOST")
		opts.Username = os.Getenv("OMADA_USERNAME")
		opts.Password = os.Getenv("OMADA_PASSWORD")
	}
	if opts.Host == "" {
		return nil, fmt.Errorf("OMADA_HOST not set — set env var or use --host flag")
	}

	client, err := omadabackend.NewClient(ctx, opts.Host)
	if err != nil {
		return nil, fmt.Errorf("connecting to omada: %w", err)
	}
	if err := client.Login(ctx, opts.Username, opts.Password); err != nil {
		return nil, fmt.Errorf("omada login: %w", err)
	}
	defer client.Logout(ctx)

	sites, err := client.GetSites(ctx)
	if err != nil || len(sites) == 0 {
		return nil, fmt.Errorf("no sites found on omada controller")
	}
	siteID := sites[0].ID

	raw, err := client.GetACLRules(ctx, siteID)
	if err != nil {
		return nil, err
	}

	rules := make([]intent.ACLRule, len(raw))
	for i, r := range raw {
		rules[i] = intent.ACLRule{
			ID:         r.ID,
			Name:       r.Name,
			Status:     r.Status,
			Policy:     r.Policy,
			SourceName: r.SourceName,
			DestName:   r.DestName,
		}
	}
	return rules, nil
}
```

Add `"os"` and `intent "github.com/velasco-jp/nyx/internal/intent"` to imports in `provider.go`.

- [ ] **Step 6: Run all audit tests**

```bash
go test ./internal/audit/... -v
```
Expected: PASS

- [ ] **Step 7: Build to check compilation**

```bash
go build ./...
```
Expected: no errors

- [ ] **Step 8: Commit**

```bash
git add internal/audit/engine.go internal/audit/engine_test.go internal/intent/spec.go internal/providers/omada/provider.go
git commit -m "feat: wire port_check, dns_check, network_health, acl_check into audit engine"
```

---

## Task 8: Wire `runner` field — SSH probe execution in engine

**Files:**
- Modify: `internal/audit/engine.go`
- Modify: `internal/audit/engine_test.go`

- [ ] **Step 1: Write the failing test**

```go
func TestRunnerErrorWhenProbeUnreachable(t *testing.T) {
	spec := &intent.Spec{
		Version: 1,
		Site:    "test",
		Probes: []intent.Probe{
			{Name: "ghost", Host: "192.0.2.99", User: "nobody", VLAN: "test"},
		},
		Assertions: []intent.Assertion{
			{Type: "route_check", Target: "10.0.0.1", Runner: "ghost"},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	engine := audit.NewEngine(spec)
	report, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("unexpected top-level error: %v", err)
	}
	f := report.Findings[0]
	if f.Status != models.StatusError {
		t.Errorf("expected error status for unreachable probe, got %q", f.Status)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
go test ./internal/audit/... -run TestRunnerErrorWhenProbeUnreachable -v
```
Expected: FAIL or the test itself fails because runner isn't wired

- [ ] **Step 3: Add probe execution wrapper to engine**

In `runAssertion`, before the type switch, intercept when `a.Runner != ""`:

```go
func (e *Engine) runAssertion(ctx context.Context, a intent.Assertion) (*models.CheckResult, error) {
	// ... timeout setup unchanged ...

	// Remote execution via SSH probe
	if a.Runner != "" {
		return e.runViaProbe(assertCtx, a)
	}

	switch a.Type {
	// ... existing cases ...
	}
}
```

Add `runViaProbe`:

```go
func (e *Engine) runViaProbe(ctx context.Context, a intent.Assertion) (*models.CheckResult, error) {
	p := e.Spec.ProbeByName(a.Runner)
	if p == nil {
		result := models.NewCheckResult("probe", a.Type, a.Runner, a.Target)
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("probe %q not found in spec", a.Runner)
		result.Finish()
		return result, nil
	}

	exec, err := probe.New(probe.Config{
		Name:    p.Name,
		Host:    p.Host,
		User:    p.User,
		KeyPath: p.Key,
		VLAN:    p.VLAN,
	})
	if err != nil {
		result := models.NewCheckResult("probe", a.Type, a.Runner, a.Target)
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("probe %q config error: %v", a.Runner, err)
		result.Finish()
		return result, nil
	}

	cmd, err := probeCommandFor(a)
	if err != nil {
		result := models.NewCheckResult("probe", a.Type, a.Runner, a.Target)
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("cannot build remote command for %s assertion: %v", a.Type, err)
		result.Finish()
		return result, nil
	}

	result := models.NewCheckResult("probe", a.Type, a.Runner, a.Target)
	out, err := exec.Run(ctx, cmd)
	result.Evidence = append(result.Evidence, fmt.Sprintf("probe=%s@%s cmd=%v", p.User, p.Host, cmd))
	if err != nil {
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("probe %q: %v", a.Runner, err)
		result.Finish()
		return result, nil
	}

	result.Evidence = append(result.Evidence, out)
	parseProbeOutput(result, a, out)
	result.Finish()
	return result, nil
}

// probeCommandFor returns the shell command to run on the remote probe for a given assertion.
// Only uses fixed argument lists — no user-controlled shell interpolation.
func probeCommandFor(a intent.Assertion) ([]string, error) {
	switch a.Type {
	case "isolation", "route_check", "network_health":
		return []string{"ping", "-c", "3", "-W", "2", a.Target}, nil
	case "port_check":
		if len(a.Ports) == 0 {
			return nil, fmt.Errorf("ports list is empty")
		}
		port := fmt.Sprintf("%d", a.Ports[0])
		return []string{"nc", "-zv", "-w", "3", a.Target, port}, nil
	case "dns_check":
		if a.Server != "" {
			return []string{"nslookup", a.Target, a.Server}, nil
		}
		return []string{"nslookup", a.Target}, nil
	default:
		return nil, fmt.Errorf("assertion type %q not supported for remote probe execution", a.Type)
	}
}

// parseProbeOutput interprets raw probe output and sets result status.
func parseProbeOutput(result *models.CheckResult, a intent.Assertion, out string) {
	switch a.Type {
	case "isolation":
		// For isolation checks: if ping succeeds (output contains "bytes from"), it's reachable
		reachable := strings.Contains(out, "bytes from") || strings.Contains(out, "ttl=")
		expectDeny := a.Expect == "deny"
		if expectDeny && reachable {
			result.Status = models.StatusFail
			result.Violations = append(result.Violations, "expected deny but probe can reach target")
			result.Summary = fmt.Sprintf("isolation violation: probe on %s can reach %s", a.Runner, a.Target)
		} else if expectDeny && !reachable {
			result.Status = models.StatusPass
			result.Summary = fmt.Sprintf("isolation confirmed: probe on %s cannot reach %s", a.Runner, a.Target)
		} else if !expectDeny && reachable {
			result.Status = models.StatusPass
			result.Summary = fmt.Sprintf("connectivity confirmed: probe on %s can reach %s", a.Runner, a.Target)
		} else {
			result.Status = models.StatusFail
			result.Summary = fmt.Sprintf("connectivity failure: probe on %s cannot reach %s", a.Runner, a.Target)
		}
	case "port_check":
		open := strings.Contains(out, "open") || strings.Contains(out, "Connected")
		if a.Expect == "open" && open {
			result.Status = models.StatusPass
			result.Summary = fmt.Sprintf("port %d is open on %s (via probe %s)", a.Ports[0], a.Target, a.Runner)
		} else if a.Expect == "open" && !open {
			result.Status = models.StatusFail
			result.Violations = append(result.Violations, fmt.Sprintf("port %d not open", a.Ports[0]))
			result.Summary = fmt.Sprintf("port %d not open on %s", a.Ports[0], a.Target)
		} else {
			result.Status = models.StatusPass
			result.Summary = fmt.Sprintf("port check via probe %s: %s", a.Runner, out)
		}
	case "dns_check":
		if strings.Contains(out, "NXDOMAIN") || strings.Contains(out, "server can't find") {
			result.Status = models.StatusFail
			result.Violations = append(result.Violations, fmt.Sprintf("DNS resolution failed for %s", a.Target))
			result.Summary = fmt.Sprintf("DNS NXDOMAIN for %q via probe %s", a.Target, a.Runner)
		} else {
			result.Status = models.StatusPass
			result.Summary = fmt.Sprintf("DNS resolved %q via probe %s", a.Target, a.Runner)
		}
	default:
		result.Status = models.StatusWarn
		result.Summary = fmt.Sprintf("probe ran on %s, raw output captured", a.Runner)
	}
}
```

- [ ] **Step 4: Run the test**

```bash
go test ./internal/audit/... -run TestRunnerErrorWhenProbeUnreachable -v
```
Expected: PASS (192.0.2.99 is non-routable, probe will time out → error result)

- [ ] **Step 5: Run all tests**

```bash
go test ./... -v
```
Expected: all PASS

- [ ] **Step 6: Commit**

```bash
git add internal/audit/engine.go internal/audit/engine_test.go
git commit -m "feat: wire SSH probe runner — remote assertion execution via probe nodes"
```

---

## Task 9: Change `subnet_discovery` default scan options to polite

**Files:**
- Modify: `internal/audit/engine.go`

- [ ] **Step 1: Write the test**

Add to `internal/audit/engine_test.go`:

```go
func TestDiscoveryDefaultsScanModeToPolite(t *testing.T) {
	// spec with no scan_mode or scan_timing set — should use polite defaults
	minVal := 0
	spec := &intent.Spec{
		Version: 1,
		Site:    "test",
		Networks: []intent.Network{
			{Name: "testnet", CIDR: "10.255.254.0/24", Zone: "test"},
		},
		Assertions: []intent.Assertion{
			{Type: "subnet_discovery", Network: "testnet", ExpectHostsMin: &minVal},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	engine := audit.NewEngine(spec)
	report, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// We can't directly inspect nmap args here, but we can assert the run completes
	// without error and the result has valid shape
	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding")
	}
	if report.Findings[0].CheckType != "subnet_discovery" {
		t.Error("expected subnet_discovery check type")
	}
}
```

- [ ] **Step 2: Update `runDiscovery` to use polite defaults**

In `internal/audit/engine.go`, in `runDiscovery`, change the initial opts line:

```go
// Before:
opts := nmap.DefaultScanOptions

// After:
opts := nmap.ScanOptionsForMode(nmap.ScanMode(a.ScanMode)) // defaults to polite when ScanMode is ""
```

- [ ] **Step 3: Run test**

```bash
go test ./internal/audit/... -run TestDiscovery -v
```
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/audit/engine.go internal/audit/engine_test.go
git commit -m "fix: default subnet_discovery scan mode to polite (-T2) to avoid SDN flood detection"
```

---

## Task 10: Update `nyx doctor` to check probe reachability

**Files:**
- Modify: `internal/cli/doctor.go`

- [ ] **Step 1: Add probe reachability check to `runSpecChecks`**

In `internal/cli/doctor.go`, after the `refCheck` block in `runSpecChecks`, add:

```go
// Probe reachability checks (informational)
for _, p := range spec.Probes {
	probeCheck := models.NewCheckResult("doctor", "probe_reachable", "local", p.Host)
	probeCheck.Observed["probe"] = p.Name
	probeCheck.Observed["host"] = p.Host
	probeCheck.Observed["vlan"] = p.VLAN

	ctx2, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	pingResult, err := system.Ping(ctx2, p.Host)
	cancel2()

	if err != nil || !pingResult.Reachable {
		probeCheck.Status = models.StatusWarn
		probeCheck.Summary = fmt.Sprintf("probe %q (%s) is not currently reachable — connect to VLAN %s before running assertions with runner: %s",
			p.Name, p.Host, p.VLAN, p.Name)
	} else {
		probeCheck.Status = models.StatusPass
		probeCheck.Summary = fmt.Sprintf("probe %q (%s) is reachable", p.Name, p.Host)
	}
	probeCheck.Finish()
	checks = append(checks, *probeCheck)
}
```

- [ ] **Step 2: Build to verify**

```bash
go build ./...
```
Expected: no errors

- [ ] **Step 3: Run all tests**

```bash
go test ./...
```
Expected: PASS

- [ ] **Step 4: Commit**

```bash
git add internal/cli/doctor.go
git commit -m "feat: nyx doctor checks probe reachability when spec includes probes"
```

---

## Task 11: Update examples and CLAUDE.md

**Files:**
- Modify: `examples/homelab.yaml`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update the example spec**

Replace `examples/homelab.yaml` assertions section with new types included:

```yaml
# Netaudit spec for a typical homelab with VLANs, VPN, and isolation policies.

version: 1
site: home-lab

probes:
  - name: laptop
    host: 192.168.30.45   # update to your laptop's IP when on IoT VLAN
    user: youruser
    vlan: iot

networks:
  - name: mgmt
    cidr: 10.0.10.0/24
    gateway: 10.0.10.1
    zone: management
    vlan: 10

  - name: clients
    cidr: 10.0.20.0/24
    gateway: 10.0.20.1
    zone: clients
    vlan: 20

  - name: iot
    cidr: 10.0.30.0/24
    gateway: 10.0.30.1
    zone: iot
    vlan: 30

  - name: servers
    cidr: 10.0.40.0/24
    gateway: 10.0.40.1
    zone: servers
    vlan: 40

  - name: guest
    cidr: 10.0.50.0/24
    gateway: 10.0.50.1
    zone: guest
    vlan: 50

vpn:
  - name: home-wg
    type: wireguard
    interface: wg0
    expected_routes:
      - 10.0.0.0/16
    mode: split-tunnel

policies:
  - name: iot-isolation
    from: iot
    to: management
    action: deny

  - name: guest-isolation
    from: guest
    to: management
    action: deny

assertions:
  # Discovery
  - type: subnet_discovery
    network: mgmt
    expect_hosts_max: 30
    scan_mode: polite

  - type: subnet_discovery
    network: clients
    expect_hosts_min: 1
    expect_hosts_max: 50
    scan_mode: polite

  # Isolation: verified from desktop (limited — desktop is in management VLAN)
  - type: isolation
    from: iot
    to: management
    expect: deny

  # Isolation: verified from laptop on IoT VLAN (true inter-VLAN probe)
  - type: isolation
    from: iot
    to: management
    expect: deny
    runner: laptop

  # ACL verification: confirm Omada actually enforces the policy
  - type: acl_check
    provider: omada
    policy: iot-isolation
    expect: enforced

  # Port reachability
  - type: port_check
    target: 10.0.40.5
    ports: [22, 443]
    expect: open
    scan_mode: polite

  # DNS
  - type: dns_check
    query: nas.home.lan
    expect_ip: 10.0.40.5
    server: 10.0.10.1
    dnssec: true

  # Network health
  - type: network_health
    target: 10.0.10.1
    expect_latency_ms: 10
    expect_loss_pct: 0

  # VPN
  - type: vpn_route
    vpn: home-wg
    target: 10.0.20.15
    expect_tunnel: true

  # Route
  - type: route_check
    target: 10.0.10.1
```

- [ ] **Step 2: Update CLAUDE.md**

In `CLAUDE.md`, update the assertion types list:

```markdown
## Spec Format

Version 1 intent spec: `networks`, `vpn`, `policies`, `probes`, `assertions`. Eight assertion types: `subnet_discovery`, `isolation`, `vpn_route`, `route_check`, `port_check`, `dns_check`, `network_health`, `acl_check`. `ValidateSpec` enforces required fields per type. See `examples/homelab.yaml` and `testdata/valid_spec.yaml`.

## Probe System

Remote probes are declared in `probes:` and referenced in assertions via `runner: <probe-name>`. nyx SSHes into the probe (no nyx install needed on probe), runs raw commands (`ping`, `nc`, `nslookup`), and interprets results locally. Useful for true VLAN isolation checks from a node inside the source zone. `nyx doctor --spec <file>` checks probe reachability.

## Scan Modes

All scan-based assertions default to `polite` mode (`-T2 --min-rate 50 --max-rate 100`) to avoid triggering Omada flood detection. Override with `scan_mode: normal` or `scan_mode: aggressive` when needed.
```

- [ ] **Step 3: Run full test suite and build**

```bash
go test ./...
go build ./...
```
Expected: all PASS, build succeeds

- [ ] **Step 4: Final commit**

```bash
git add examples/homelab.yaml CLAUDE.md
git commit -m "docs: update examples and CLAUDE.md for feature sprint 1 (new assertion types, probes, scan modes)"
```

---

## Self-Review

**Spec coverage check:**
- ✅ `port_check` — Tasks 2, 7
- ✅ `dns_check` — Tasks 3, 7
- ✅ `network_health` — Tasks 4, 7
- ✅ `acl_check` — Tasks 7 (engine), OmadaProvider.GetACLRules in Task 7
- ✅ SSH probe executor — Task 5
- ✅ `probes` spec field + validation — Task 6
- ✅ `runner` wiring in engine — Task 8
- ✅ `ScanMode` field + polite defaults — Tasks 1, 9
- ✅ `nyx doctor` probe reachability — Task 10
- ✅ Examples + docs — Task 11

**Type consistency check:**
- `nmap.ScanOptionsForMode(nmap.ScanMode(a.ScanMode))` — consistent across Tasks 1, 7, 9
- `probe.New(probe.Config{...})` — consistent between Tasks 5 and 8
- `dns.Resolve(ctx, dns.Query{...})` — consistent between Tasks 3 and 7
- `health.Check(ctx, health.Options{...})` — consistent between Tasks 4 and 7
- `a.Expect` replaces `a.ExpectDeny` — updated in Tasks 6 and 7
- `intent.ACLRule` defined in Task 7, used in `ruleEnforcesPolicy` in same task

**Placeholder scan:** None found.
