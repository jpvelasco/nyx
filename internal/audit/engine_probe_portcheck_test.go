package audit

import (
	"context"
	"net"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jpvelasco/nyx/internal/backends"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/probe/fake"
)

// remotePortCheckTarget is the synthetic check target used by the remote
// port-check tests (docs/naming.md servers-VLAN fixture value).
const remotePortCheckTarget = "10.0.40.1"

// lastPortOf extracts the port argument from a shell-quoted remote command
// line such as `nc -z -w 3 10.0.40.1 '80'` (the final field, quote-stripped).
func lastPortOf(cmd string) int {
	fields := strings.Fields(cmd)
	if len(fields) == 0 {
		return 0
	}
	port, err := strconv.Atoi(strings.Trim(fields[len(fields)-1], `'`))
	if err != nil {
		return 0
	}
	return port
}

// portExitServer starts a fake SSH server whose remote netcat behavior is
// driven by openPorts: exit 0 for ports in the set, exit 1 otherwise.
func portExitServer(t *testing.T, openPorts map[int]bool) *fake.Server {
	t.Helper()
	return fake.Start(t, fake.Options{
		ExecReply: true,
		OnExec: func(cmd string) (string, uint32) {
			if openPorts[lastPortOf(cmd)] {
				return "", 0
			}
			return "", 1
		},
	})
}

// newPortCheckProbeEngine builds an engine whose single probe reaches a live
// fake SSH server, so eng.runViaProbe exercises the real dispatch path.
func newPortCheckProbeEngine(t *testing.T, srv *fake.Server) *Engine {
	t.Helper()
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	fake.WriteKey(t, keyPath)
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Probes: []intent.Probe{
			{Name: "probe1", Host: "127.0.0.1", User: "testuser", Port: srv.Port, Key: keyPath},
		},
	}
	eng := NewEngine(spec)
	eng.Backend = &backends.MockBackend{}
	eng.SkipHostKeyVerify = true
	return eng
}

func remotePortCheck(t *testing.T, eng *Engine, a intent.Assertion) *models.CheckResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := eng.runViaProbe(ctx, a)
	if err != nil {
		t.Fatalf("runViaProbe: %v", err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	return result
}

func requireObservedStates(t *testing.T, result *models.CheckResult, want map[int]string) {
	t.Helper()
	obs, ok := result.Observed["ports"].([]interface{})
	if !ok {
		t.Fatalf("expected Observed[\"ports\"] to be a list, got %T", result.Observed["ports"])
	}
	if len(obs) != len(want) {
		t.Fatalf("expected %d observed port rows, got %d", len(want), len(obs))
	}
	seen := map[int]string{}
	for _, row := range obs {
		pm, ok := row.(map[string]interface{})
		if !ok {
			t.Fatalf("expected observed port row to be a map, got %T", row)
		}
		port, _ := pm["port"].(float64)
		state, _ := pm["state"].(string)
		seen[int(port)] = state
	}
	for port, state := range want {
		if got := seen[port]; got != state {
			t.Errorf("port %d: observed state %q, want %q", port, got, state)
		}
	}
}

func requireExpectedPorts(t *testing.T, result *models.CheckResult, want []int) {
	t.Helper()
	ports, ok := result.Expected["ports"].([]int)
	if !ok || !slices.Equal(ports, want) {
		t.Errorf("Expected[\"ports\"] = %v, want %v", result.Expected["ports"], want)
	}
}

// #268 regression pair: with two requested ports the first open and the
// second closed, expect: open must fail — today only the first port is
// checked, so the assertion silently passes.
func TestRunPortCheckViaProbe_MixedPortsExpectOpenFails(t *testing.T) {
	eng := newPortCheckProbeEngine(t, portExitServer(t, map[int]bool{80: true}))
	a := intent.Assertion{Type: "port_check", Runner: "probe1", Target: remotePortCheckTarget, Ports: []int{80, 443}, Expect: "open"}
	result := remotePortCheck(t, eng, a)
	if result.Status != models.StatusFail {
		t.Fatalf("expected FAIL (443 closed, expect open), got %s: %s", result.Status, result.Summary)
	}
	if !slices.Contains(result.Violations, "port 443: expected open, got closed") {
		t.Errorf("violation should name port 443, got %v", result.Violations)
	}
	if slices.Contains(result.Violations, "port 80") {
		t.Errorf("port 80 matched; it must not appear in violations, got %v", result.Violations)
	}
	requireExpectedPorts(t, result, []int{80, 443})
	requireObservedStates(t, result, map[int]string{80: "open", 443: "closed"})
	if !slices.Contains(result.Evidence, "port 80: open") || !slices.Contains(result.Evidence, "port 443: closed") {
		t.Errorf("evidence should carry a measured line per port, got %v", result.Evidence)
	}
}

// #268 regression pair, mirrored: first closed, second open, expect: closed
// must fail on the second port.
func TestRunPortCheckViaProbe_MixedPortsExpectClosedFails(t *testing.T) {
	eng := newPortCheckProbeEngine(t, portExitServer(t, map[int]bool{443: true}))
	a := intent.Assertion{Type: "port_check", Runner: "probe1", Target: remotePortCheckTarget, Ports: []int{80, 443}, Expect: "closed"}
	result := remotePortCheck(t, eng, a)
	if result.Status != models.StatusFail {
		t.Fatalf("expected FAIL (443 open, expect closed), got %s: %s", result.Status, result.Summary)
	}
	if !slices.Contains(result.Violations, "port 443: expected closed, got open") {
		t.Errorf("violation should name port 443, got %v", result.Violations)
	}
	requireExpectedPorts(t, result, []int{80, 443})
	requireObservedStates(t, result, map[int]string{80: "closed", 443: "open"})
}

func TestRunPortCheckViaProbe_AllOpenPasses(t *testing.T) {
	eng := newPortCheckProbeEngine(t, portExitServer(t, map[int]bool{80: true, 443: true}))
	a := intent.Assertion{Type: "port_check", Runner: "probe1", Target: remotePortCheckTarget, Ports: []int{80, 443}, Expect: "open"}
	result := remotePortCheck(t, eng, a)
	if result.Status != models.StatusPass {
		t.Fatalf("expected PASS, got %s: %s", result.Status, result.Summary)
	}
	requireExpectedPorts(t, result, []int{80, 443})
	requireObservedStates(t, result, map[int]string{80: "open", 443: "open"})
}

func TestRunPortCheckViaProbe_AllClosedPasses(t *testing.T) {
	eng := newPortCheckProbeEngine(t, portExitServer(t, map[int]bool{}))
	a := intent.Assertion{Type: "port_check", Runner: "probe1", Target: remotePortCheckTarget, Ports: []int{80, 443}, Expect: "closed"}
	result := remotePortCheck(t, eng, a)
	if result.Status != models.StatusPass {
		t.Fatalf("expected PASS, got %s: %s", result.Status, result.Summary)
	}
	requireObservedStates(t, result, map[int]string{80: "closed", 443: "closed"})
}

// Single-port assertions stay covered by the same per-port path.
func TestRunPortCheckViaProbe_SinglePort(t *testing.T) {
	eng := newPortCheckProbeEngine(t, portExitServer(t, map[int]bool{80: true}))
	a := intent.Assertion{Type: "port_check", Runner: "probe1", Target: remotePortCheckTarget, Ports: []int{80}, Expect: "open"}
	result := remotePortCheck(t, eng, a)
	if result.Status != models.StatusPass {
		t.Fatalf("expected PASS, got %s: %s", result.Status, result.Summary)
	}
	requireObservedStates(t, result, map[int]string{80: "open"})
}

// netcat missing on the probe (exit 127) is an unmeasured dependency
// failure: the assertion must degrade to WARN, never PASS or FAIL.
func TestRunPortCheckViaProbe_NetcatMissingIsUnverifiable(t *testing.T) {
	srv := fake.Start(t, fake.Options{ExecReply: true, OnExec: func(cmd string) (string, uint32) {
		return "", 127
	}})
	eng := newPortCheckProbeEngine(t, srv)
	a := intent.Assertion{Type: "port_check", Runner: "probe1", Target: remotePortCheckTarget, Ports: []int{80, 443}, Expect: "open"}
	result := remotePortCheck(t, eng, a)
	if result.Status != models.StatusWarn {
		t.Fatalf("expected WARN (unmeasured), got %s: %s", result.Status, result.Summary)
	}
	if !strings.Contains(result.Summary, "unverifiable") {
		t.Errorf("summary should say unverifiable, got %q", result.Summary)
	}
}

// One port measured, one unmeasured: partial verification is WARN, and a
// measured violation still FAILs with priority.
func TestRunPortCheckViaProbe_PartialUnmeasured(t *testing.T) {
	srv := fake.Start(t, fake.Options{ExecReply: true, OnExec: func(cmd string) (string, uint32) {
		if lastPortOf(cmd) == 80 {
			return "", 127 // netcat missing only for this invocation
		}
		return "", 0
	}})
	eng := newPortCheckProbeEngine(t, srv)
	a := intent.Assertion{Type: "port_check", Runner: "probe1", Target: remotePortCheckTarget, Ports: []int{80, 443}, Expect: "open"}
	result := remotePortCheck(t, eng, a)
	if result.Status != models.StatusWarn {
		t.Fatalf("expected WARN (partially verified), got %s: %s", result.Status, result.Summary)
	}
	if !strings.Contains(result.Summary, "partially verified") {
		t.Errorf("summary should say partially verified, got %q", result.Summary)
	}

	aFail := a
	aFail.Ports = []int{80, 443}
	aFail.Expect = "closed" // measured 443 open violates → FAIL beats partial
	result = remotePortCheck(t, eng, aFail)
	if result.Status != models.StatusFail {
		t.Fatalf("expected FAIL (measured violation), got %s: %s", result.Status, result.Summary)
	}
	if !slices.Contains(result.Violations, "port 443: expected closed, got open") {
		t.Errorf("violation should name port 443, got %v", result.Violations)
	}
}

// Remote probes can only run TCP netcat; other protocols must be refused
// with an actionable error, not silently checked as TCP.
func TestRunPortCheckViaProbe_NonTCPProtocolRejected(t *testing.T) {
	eng := newPortCheckProbeEngine(t, portExitServer(t, map[int]bool{80: true}))
	a := intent.Assertion{Type: "port_check", Runner: "probe1", Target: remotePortCheckTarget, Ports: []int{80}, Expect: "open", Protocol: "udp"}
	result := remotePortCheck(t, eng, a)
	if result.Status != models.StatusError {
		t.Fatalf("expected ERROR for unsupported protocol, got %s: %s", result.Status, result.Summary)
	}
	if !strings.Contains(strings.ToLower(result.Summary), "udp") {
		t.Errorf("summary should name the rejected protocol, got %q", result.Summary)
	}
}

// Probe transport failure (dead listener) leaves every port unmeasured:
// the assertion degrades to WARN "unverifiable" and never PASSes.
func TestRunPortCheckViaProbe_TransportFailureIsUnverifiable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close() // freed port — dial is refused

	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	fake.WriteKey(t, keyPath)
	spec := &intent.Spec{
		Version: 1, Site: "test",
		Probes: []intent.Probe{
			{Name: "probe1", Host: "127.0.0.1", User: "testuser", Port: port, Key: keyPath},
		},
	}
	eng := NewEngine(spec)
	eng.Backend = &backends.MockBackend{}
	eng.SkipHostKeyVerify = true
	a := intent.Assertion{Type: "port_check", Runner: "probe1", Target: remotePortCheckTarget, Ports: []int{80, 443}, Expect: "open"}
	result := remotePortCheck(t, eng, a)
	if result.Status != models.StatusWarn {
		t.Fatalf("expected WARN (unmeasured), got %s: %s", result.Status, result.Summary)
	}
	if !strings.Contains(result.Summary, "unverifiable") {
		t.Errorf("summary should say unverifiable, got %q", result.Summary)
	}
}

// A cancelled context before the run leaves no measured ports: the result
// must be WARN, never a PASS built on unevaluated ports.
func TestRunPortCheckViaProbe_CancelledContextIsUnverifiable(t *testing.T) {
	eng := newPortCheckProbeEngine(t, portExitServer(t, map[int]bool{80: true, 443: true}))
	a := intent.Assertion{Type: "port_check", Runner: "probe1", Target: remotePortCheckTarget, Ports: []int{80, 443}, Expect: "open"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := eng.runViaProbe(ctx, a)
	if err != nil {
		t.Fatalf("runViaProbe: %v", err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	if result.Status != models.StatusWarn {
		t.Fatalf("expected WARN (unmeasured), got %s: %s", result.Status, result.Summary)
	}
}

func TestEvalPortCheckVerdict(t *testing.T) {
	tests := []struct {
		name       string
		expectOpen bool
		ports      []int
		states     []string
		wantStatus models.Status
		wantSubstr string
		wantViol   []string
	}{
		{
			name:       "all open expect open passes",
			expectOpen: true, ports: []int{80, 443}, states: []string{"open", "open"},
			wantStatus: models.StatusPass, wantSubstr: "all 2 port(s) open",
		},
		{
			name:       "all closed expect closed passes",
			expectOpen: false, ports: []int{80, 443}, states: []string{"closed", "closed"},
			wantStatus: models.StatusPass, wantSubstr: "all 2 port(s) closed",
		},
		{
			name:       "mixed with closed port fails expect open",
			expectOpen: true, ports: []int{80, 443}, states: []string{"open", "closed"},
			wantStatus: models.StatusFail, wantSubstr: "port check failed",
			wantViol: []string{"port 443: expected open, got closed"},
		},
		{
			name:       "mixed with open port fails expect closed",
			expectOpen: false, ports: []int{80, 443}, states: []string{"closed", "open"},
			wantStatus: models.StatusFail, wantSubstr: "port check failed",
			wantViol: []string{"port 443: expected closed, got open"},
		},
		{
			name:       "filtered counts as not open",
			expectOpen: true, ports: []int{80}, states: []string{"filtered"},
			wantStatus: models.StatusFail,
			wantViol:   []string{"port 80: expected open, got filtered"},
		},
		{
			name:       "all unmeasured is unverifiable",
			expectOpen: true, ports: []int{80, 443}, states: []string{"unmeasured", "unmeasured"},
			wantStatus: models.StatusWarn, wantSubstr: "unverifiable",
		},
		{
			name:       "partial unmeasured is partially verified",
			expectOpen: true, ports: []int{80, 443}, states: []string{"unmeasured", "open"},
			wantStatus: models.StatusWarn, wantSubstr: "partially verified",
		},
		{
			name:       "measured violation beats partial",
			expectOpen: false, ports: []int{80, 443}, states: []string{"unmeasured", "open"},
			wantStatus: models.StatusFail,
			wantViol:   []string{"port 443: expected closed, got open"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, summary, violations := evalPortCheckVerdict(remotePortCheckTarget, "probe1", tt.expectOpen, tt.ports, tt.states)
			if status != tt.wantStatus {
				t.Fatalf("status = %s, want %s (%s)", status, tt.wantStatus, summary)
			}
			if !strings.Contains(summary, tt.wantSubstr) {
				t.Errorf("summary %q should contain %q", summary, tt.wantSubstr)
			}
			if len(violations) != len(tt.wantViol) {
				t.Fatalf("violations = %v, want %v", violations, tt.wantViol)
			}
			for i := range tt.wantViol {
				if violations[i] != tt.wantViol[i] {
					t.Errorf("violation[%d] = %q, want %q", i, violations[i], tt.wantViol[i])
				}
			}
		})
	}
}
