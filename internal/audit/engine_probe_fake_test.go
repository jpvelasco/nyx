package audit

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jpvelasco/nyx/internal/backends"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/probe/fake"
)

// --- runViaProbe / runIsolationViaProbe over the in-process fake SSH server ---
//
// Engine probe dispatch goes through probe.Run, which needs a live SSH
// peer. These tests run the existing in-process fake SSH server so the
// success, remote-failure, and partial-coverage verdicts execute on every
// platform without an external host. The fake server rejects exec
// requests unless ExecReply is set, so every Options literal opts in.

// startFakeProbe starts the in-process fake SSH server, writes a
// throwaway client key, and returns the spec probe entry pointed at the
// server. The server and key are cleaned up when the test ends.
func startFakeProbe(t *testing.T, opts fake.Options) intent.Probe {
	t.Helper()
	srv := fake.Start(t, opts)
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	fake.WriteKey(t, keyPath)
	return intent.Probe{
		Name: "fakeprobe",
		Host: "127.0.0.1",
		Port: srv.Port,
		User: "test",
		Key:  keyPath,
		VLAN: "test",
	}
}

// newProbeEngine builds an engine whose spec carries the fake probe and
// whose host-key verification is bypassed, ready for runViaProbe dispatch.
func newProbeEngine(t *testing.T, spec *intent.Spec, opts fake.Options) *Engine {
	t.Helper()
	spec.Probes = append(spec.Probes, startFakeProbe(t, opts))
	eng := NewEngine(spec)
	eng.Backend = &backends.MockBackend{}
	eng.SkipHostKeyVerify = true
	return eng
}

// fakePingOutput builds a realistic iputils ping transcript for the target.
func fakePingOutput(target string, blocked bool) string {
	if blocked {
		return fmt.Sprintf("PING %s (%s) 56(84) bytes of data.\n\n--- %s ping statistics ---\n3 packets transmitted, 0 received, 100%% packet loss, time 2005ms\n", target, target, target)
	}
	return fmt.Sprintf("PING %s (%s) 56(84) bytes of data.\n64 bytes from %s: icmp_seq=1 ttl=64 time=0.41 ms\n64 bytes from %s: icmp_seq=2 ttl=64 time=0.42 ms\n64 bytes from %s: icmp_seq=3 ttl=64 time=0.40 ms\n\n--- %s ping statistics ---\n3 packets transmitted, 3 received, 0%% packet loss, time 2002ms\n", target, target, target, target, target, target)
}

// A remote command that ran and exited non-zero is a value signal: it is
// evaluated against the assertion (parseProbeOutput with remoteFailed),
// never treated as an execution error.
func TestRunViaProbe_RemoteFailureEvaluatesOutput(t *testing.T) {
	spec := &intent.Spec{Version: 1, Site: "test"}
	eng := newProbeEngine(t, spec, fake.Options{
		ExecReply: true,
		OnExec: func(string) (string, uint32) {
			return fakePingOutput("10.0.0.5", true), 1
		},
	})
	a := intent.Assertion{Type: "network_health", Target: "10.0.0.5", Runner: "fakeprobe"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := eng.runViaProbe(ctx, a)
	if err != nil {
		t.Fatalf("runViaProbe: %v", err)
	}
	if result.Status != models.StatusFail {
		t.Fatalf("status = %v, want StatusFail (summary: %s)", result.Status, result.Summary)
	}
	want := "100% packet loss to 10.0.0.5 from probe \"fakeprobe\""
	if result.Summary != want {
		t.Errorf("summary = %q, want %q", result.Summary, want)
	}
	if len(result.Violations) != 1 || result.Violations[0] != "100% packet loss" {
		t.Errorf("violations = %v, want [100%% packet loss]", result.Violations)
	}
}

// A clean remote exit surfaces the parsed success verdict.
func TestRunViaProbe_RemoteSuccess(t *testing.T) {
	spec := &intent.Spec{Version: 1, Site: "test"}
	eng := newProbeEngine(t, spec, fake.Options{
		ExecReply: true,
		OnExec: func(string) (string, uint32) {
			return fakePingOutput("10.0.0.5", false), 0
		},
	})
	a := intent.Assertion{Type: "network_health", Target: "10.0.0.5", Runner: "fakeprobe"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := eng.runViaProbe(ctx, a)
	if err != nil {
		t.Fatalf("runViaProbe: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Fatalf("status = %v, want StatusPass (summary: %s)", result.Status, result.Summary)
	}
	want := "host 10.0.0.5 is reachable from probe \"fakeprobe\""
	if result.Summary != want {
		t.Errorf("summary = %q, want %q", result.Summary, want)
	}
	assertProbeOutputWithheld(t, result, fakePingOutput("10.0.0.5", false))
}

func assertProbeOutputWithheld(t *testing.T, result *models.CheckResult, output string) {
	t.Helper()
	want := fmt.Sprintf("remote output: %d bytes (content withheld)", len(output))
	if !slices.Contains(result.Evidence, want) || slices.Contains(result.Evidence, output) {
		t.Errorf("evidence = %q, want size only (%q)", result.Evidence, want)
	}
}

// Every gateway tested and blocked confirms isolation from the probe.
func TestRunIsolationViaProbe_AllGatewaysBlocked(t *testing.T) {
	spec := &intent.Spec{
		Version:  1,
		Site:     "test",
		Networks: []intent.Network{{Name: "net1", CIDR: "10.0.0.0/24", Gateway: "10.0.0.1", Zone: "zone1"}},
	}
	eng := newProbeEngine(t, spec, fake.Options{
		ExecReply: true,
		OnExec: func(string) (string, uint32) {
			return fakePingOutput("10.0.0.1", true), 1
		},
	})
	a := intent.Assertion{Type: "isolation", From: "trusted", To: "zone1", Expect: "deny", Runner: "fakeprobe"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := eng.runViaProbe(ctx, a)
	if err != nil {
		t.Fatalf("runViaProbe: %v", err)
	}
	if result.Status != models.StatusPass {
		t.Fatalf("status = %v, want StatusPass (summary: %s)", result.Status, result.Summary)
	}
	want := "isolation confirmed from probe \"fakeprobe\": trusted cannot reach zone1"
	if result.Summary != want {
		t.Errorf("summary = %q, want %q", result.Summary, want)
	}
	if len(result.Violations) != 0 {
		t.Errorf("violations = %v, want none", result.Violations)
	}
	if !slices.Contains(result.Evidence, "gateway 10.0.0.1: blocked") {
		t.Errorf("evidence missing blocked gateway marker: %v", result.Evidence)
	}
	assertProbeOutputWithheld(t, result, fakePingOutput("10.0.0.1", true))
}

// A reachable gateway against a deny expectation is a violation.
func TestRunIsolationViaProbe_GatewayReachable(t *testing.T) {
	spec := &intent.Spec{
		Version:  1,
		Site:     "test",
		Networks: []intent.Network{{Name: "net1", CIDR: "10.0.0.0/24", Gateway: "10.0.0.1", Zone: "zone1"}},
	}
	eng := newProbeEngine(t, spec, fake.Options{
		ExecReply: true,
		OnExec: func(string) (string, uint32) {
			return fakePingOutput("10.0.0.1", false), 0
		},
	})
	a := intent.Assertion{Type: "isolation", From: "trusted", To: "zone1", Expect: "deny", Runner: "fakeprobe"}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := eng.runViaProbe(ctx, a)
	if err != nil {
		t.Fatalf("runViaProbe: %v", err)
	}
	if result.Status != models.StatusFail {
		t.Fatalf("status = %v, want StatusFail (summary: %s)", result.Status, result.Summary)
	}
	want := "isolation violation from probe \"fakeprobe\": trusted can reach zone1"
	if result.Summary != want {
		t.Errorf("summary = %q, want %q", result.Summary, want)
	}
	if !slices.Contains(result.Violations, "expected deny but traffic is reachable from probe VLAN") {
		t.Errorf("violations = %v, want the expected-deny violation", result.Violations)
	}
	if !slices.Contains(result.Evidence, "gateway 10.0.0.1: reachable") {
		t.Errorf("evidence missing reachable gateway marker: %v", result.Evidence)
	}
}

// When one gateway is blocked but another cannot be tested at all (the
// remote ping outlives the caller's context deadline), the pass verdict
// degrades to a partial-coverage warning instead of a confirmed isolation.
func TestRunIsolationViaProbe_PartialUnreachedWarns(t *testing.T) {
	spec := &intent.Spec{
		Version: 1,
		Site:    "test",
		Networks: []intent.Network{
			{Name: "net-a", CIDR: "10.0.0.0/24", Gateway: "10.0.0.1", Zone: "zone1"},
			{Name: "net-b", CIDR: "10.0.1.0/24", Gateway: "10.0.1.1", Zone: "zone1"},
		},
	}
	eng := newProbeEngine(t, spec, fake.Options{
		ExecReply: true,
		OnExec: func(cmd string) (string, uint32) {
			if strings.Contains(cmd, "10.0.1.1") {
				// Outlive the caller's deadline so the probe aborts
				// mid-command and the gateway counts as untested.
				time.Sleep(30 * time.Second)
				return "", 0
			}
			return fakePingOutput("10.0.0.1", true), 1
		},
	})
	a := intent.Assertion{Type: "isolation", From: "trusted", To: "zone1", Expect: "deny", Runner: "fakeprobe"}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	result, err := eng.runViaProbe(ctx, a)
	if err != nil {
		t.Fatalf("runViaProbe: %v", err)
	}
	if result.Status != models.StatusWarn {
		t.Fatalf("status = %v, want StatusWarn (partial coverage degrades the pass; summary: %s)", result.Status, result.Summary)
	}
	want := "isolation partially verified: 1 gateway(s) could not be tested from probe \"fakeprobe\" (trusted → zone1)"
	if result.Summary != want {
		t.Errorf("summary = %q, want %q", result.Summary, want)
	}
	if !slices.Contains(result.Evidence, "gateway 10.0.1.1: probe unreachable (context deadline exceeded)") {
		t.Errorf("evidence missing unreachable gateway marker: %v", result.Evidence)
	}
}
