package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/probe/fake"
)

// lastTestServerPort tracks the ephemeral port of the most recently started
// test SSH server so testProbe can point Run/Check at it. Tests start their
// server before building the probe, so the value is always the right one.
var lastTestServerPort int

// startTestSSHServer binds an ephemeral loopback port and serves SSH in the
// background via the shared fake SSH server (internal/probe/fake). The bound
// port is recorded in lastTestServerPort so testProbe points Run/Check at
// the running server. Ephemeral ports avoid privileged port 22 so these
// tests also run on rootless CI runners.
func startTestSSHServer(t *testing.T, hangExec bool, rejectSessions bool, execReply bool, exitStatus uint32) *fake.Server {
	t.Helper()
	return startTestSSHServerWithOptions(t, hangExec, rejectSessions, execReply, exitStatus, false)
}

// startTestSSHServerRejectingKeys is like startTestSSHServer, but the server
// rejects every public key so client-side auth failures can be exercised
// without racing a config mutation against the serve goroutine.
func startTestSSHServerRejectingKeys(t *testing.T, hangExec bool, rejectSessions bool, execReply bool, exitStatus uint32) *fake.Server {
	t.Helper()
	return startTestSSHServerWithOptions(t, hangExec, rejectSessions, execReply, exitStatus, true)
}

func startTestSSHServerWithOptions(t *testing.T, hangExec bool, rejectSessions bool, execReply bool, exitStatus uint32, rejectKeys bool) *fake.Server {
	t.Helper()
	srv := fake.Start(t, fake.Options{
		HangExec:       hangExec,
		RejectSessions: rejectSessions,
		ExecReply:      execReply,
		RejectKeys:     rejectKeys,
		ExitStatus:     exitStatus,
	})
	lastTestServerPort = srv.Port
	return srv
}

// writeTestKey writes a fresh ed25519 private key in OpenSSH format.
func writeTestKey(t *testing.T, path string) {
	fake.WriteKey(t, path)
}

// withTestHome points os.UserHomeDir at an empty temp dir for the test's
// duration (t.Setenv restores the real value), so known_hosts resolution
// never touches the developer's real trust store.
func withTestHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	} else {
		t.Setenv("HOME", home)
	}
	return home
}

// writeKnownHosts writes one entry line to <home>/.ssh/known_hosts.
func writeKnownHosts(t *testing.T, home, line string) {
	t.Helper()
	dir := filepath.Join(home, ".ssh")
	// 0o700 is the minimum usable directory mode (owner execute bit); the
	// pattern's 0600 ceiling applies to files, not directories.
	if err := os.MkdirAll(dir, 0o700); err != nil { // nosemgrep: go.lang.correctness.permissions.file_permission.incorrect-default-permission
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "known_hosts"), []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// knownHostsLine renders srv's host key for the dialed [host]:port address,
// the entry form a probe on a non-default port needs.
func knownHostsLine(t *testing.T, srv *fake.Server, host string) string {
	t.Helper()
	return knownhosts.Line([]string{fmt.Sprintf("[%s]:%d", host, srv.Port)}, srv.HostKey())
}

func testProbe(host string) Probe {
	return Probe{Name: "p1", Host: host, User: "testuser", VLAN: "iot", Port: lastTestServerPort}
}

func TestRun_SuccessWithKeyAuth(t *testing.T) {
	startTestSSHServer(t, false, false, true, 0)
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	writeTestKey(t, keyPath)

	p := testProbe("127.0.0.1")
	p.Key = keyPath
	out, err := Run(context.Background(), p, []string{"echo", "hello world"}, true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, `'hello world'`) {
		t.Errorf("output should contain shell-quoted args, got %q", out)
	}
}

func TestRun_HostKeyVerificationFailure(t *testing.T) {
	startTestSSHServer(t, false, false, true, 0)
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	writeTestKey(t, keyPath)
	// An empty trust store makes the rejection deterministic and hermetic:
	// the freshly generated host key is never in the developer's real
	// known_hosts.
	withTestHome(t)

	p := testProbe("127.0.0.1")
	p.Key = keyPath
	_, err := Run(context.Background(), p, []string{"echo", "hi"}, false)
	if err == nil {
		t.Fatal("expected host key verification failure")
	}
	var hostKeyErr *HostKeyError
	if !errors.As(err, &hostKeyErr) {
		t.Fatalf("expected *HostKeyError, got %T: %v", err, err)
	}
	for _, want := range []string{`probe "p1"`, "host key verification failed", "--skip-host-key-verify"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}
}

// TestRun_KnownHostsTrustedKeySucceeds pins #272 AC-1 for Run: with host
// key verification ON and the server's key pre-registered in a temporary
// known_hosts, the handshake and command succeed.
func TestRun_KnownHostsTrustedKeySucceeds(t *testing.T) {
	srv := startTestSSHServer(t, false, false, true, 0)
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	writeTestKey(t, keyPath)
	home := withTestHome(t)
	writeKnownHosts(t, home, knownHostsLine(t, srv, "127.0.0.1"))

	p := testProbe("127.0.0.1")
	p.Key = keyPath
	out, err := Run(context.Background(), p, []string{"echo", "trusted"}, false)
	if err != nil {
		t.Fatalf("trusted known_hosts key must verify, got: %v", err)
	}
	if !strings.Contains(out, "'trusted'") {
		t.Errorf("output should contain the echoed command, got %q", out)
	}
}

// TestDiagnose_KnownHostsTrustedKeySucceeds pins AC-1 for the read-only
// diagnose path (nyx doctor --spec / MCP run_doctor).
func TestDiagnose_KnownHostsTrustedKeySucceeds(t *testing.T) {
	srv := startTestSSHServer(t, false, false, true, 0)
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	writeTestKey(t, keyPath)
	home := withTestHome(t)
	writeKnownHosts(t, home, knownHostsLine(t, srv, "127.0.0.1"))

	p := testProbe("127.0.0.1")
	p.Key = keyPath
	if err := Diagnose(context.Background(), p); err != nil {
		t.Fatalf("trusted known_hosts key must verify, got: %v", err)
	}
}

// TestRun_KnownHostsUnknownKeyRejected pins AC-2: a key absent from the
// (present) trust file fails as HostKeyError with install guidance,
// including the [host]:port entry form for non-default ports.
func TestRun_KnownHostsUnknownKeyRejected(t *testing.T) {
	srv := startTestSSHServer(t, false, false, true, 0)
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	writeTestKey(t, keyPath)
	home := withTestHome(t)
	// An entry for a different host: the dialed host is unknown.
	writeKnownHosts(t, home, knownhosts.Line([]string{"example.invalid"}, srv.HostKey()))

	p := testProbe("127.0.0.1")
	p.Key = keyPath
	_, err := Run(context.Background(), p, []string{"echo", "hi"}, false)
	var hostKeyErr *HostKeyError
	if !errors.As(err, &hostKeyErr) {
		t.Fatalf("expected *HostKeyError, got %T: %v", err, err)
	}
	for _, want := range []string{`probe "p1"`, "host key verification failed", fmt.Sprintf("[127.0.0.1]:%d", srv.Port), "ssh-keyscan", "--skip-host-key-verify"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}
}

// TestRun_KnownHostsChangedKeyRejected pins AC-2: a changed key (entry
// present, key differs) fails as HostKeyError with mismatch guidance — no
// silent acceptance, no trust-on-first-use.
func TestRun_KnownHostsChangedKeyRejected(t *testing.T) {
	srv := startTestSSHServer(t, false, false, true, 0)
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	writeTestKey(t, keyPath)
	home := withTestHome(t)

	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherSigner, err := ssh.NewSignerFromKey(other)
	if err != nil {
		t.Fatal(err)
	}
	writeKnownHosts(t, home, knownhosts.Line([]string{fmt.Sprintf("[127.0.0.1]:%d", srv.Port)}, otherSigner.PublicKey()))

	p := testProbe("127.0.0.1")
	p.Key = keyPath
	_, err = Run(context.Background(), p, []string{"echo", "hi"}, false)
	var hostKeyErr *HostKeyError
	if !errors.As(err, &hostKeyErr) {
		t.Fatalf("expected *HostKeyError, got %T: %v", err, err)
	}
	for _, want := range []string{"does not match", "known_hosts"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}
}

// TestRun_KnownHostsUnreadableFileRejected pins AC-2: an unparseable trust
// file is a fail-closed HostKeyError naming the path, not a transport
// failure and not a silent verification bypass.
func TestRun_KnownHostsUnreadableFileRejected(t *testing.T) {
	startTestSSHServer(t, false, false, true, 0)
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	writeTestKey(t, keyPath)
	home := withTestHome(t)
	writeKnownHosts(t, home, "this is not a valid known_hosts line")

	p := testProbe("127.0.0.1")
	p.Key = keyPath
	_, err := Run(context.Background(), p, []string{"echo", "hi"}, false)
	var hostKeyErr *HostKeyError
	if !errors.As(err, &hostKeyErr) {
		t.Fatalf("expected *HostKeyError, got %T: %v", err, err)
	}
	for _, want := range []string{"missing or unreadable", ".ssh", "known_hosts", "--skip-host-key-verify"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}
}

// TestRun_KnownHostsBareHostEntryDoesNotMatchNonDefaultPort pins AC-3: a
// known_hosts entry for the bare host (port 22) must not satisfy a probe
// dialing a non-default port — the port is part of the match.
func TestRun_KnownHostsBareHostEntryDoesNotMatchNonDefaultPort(t *testing.T) {
	srv := startTestSSHServer(t, false, false, true, 0)
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	writeTestKey(t, keyPath)
	home := withTestHome(t)
	writeKnownHosts(t, home, knownhosts.Line([]string{"127.0.0.1"}, srv.HostKey()))

	p := testProbe("127.0.0.1")
	p.Key = keyPath
	_, err := Run(context.Background(), p, []string{"echo", "hi"}, false)
	var hostKeyErr *HostKeyError
	if !errors.As(err, &hostKeyErr) {
		t.Fatalf("expected *HostKeyError for a port-22 entry against a non-default port, got %T: %v", err, err)
	}
}

func TestRun_NoAuthMethods(t *testing.T) {
	startTestSSHServer(t, false, false, true, 0)
	t.Setenv("SSH_AUTH_SOCK", "")

	p := testProbe("127.0.0.1")
	_, err := Run(context.Background(), p, []string{"echo", "hi"}, true)
	if err == nil {
		t.Fatal("expected no-auth-methods error")
	}
	if !strings.Contains(err.Error(), "no authentication methods available") {
		t.Errorf("error = %v", err)
	}
}

func TestRun_CommandError(t *testing.T) {
	startTestSSHServer(t, false, false, true, 1)
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	writeTestKey(t, keyPath)

	p := testProbe("127.0.0.1")
	p.Key = keyPath
	out, err := Run(context.Background(), p, []string{"false"}, true)
	if err == nil {
		t.Fatal("expected command error")
	}
	if !strings.Contains(out, "'false'") {
		t.Errorf("output should still carry echoed command, got %q", out)
	}
}

// TestRun_RemoteErrorCarriesExitStatus pins the shell exit statuses that
// distinguish a measured result (1 = command ran, condition false) from a
// dependency failure (126/127 = command missing or not executable).
func TestRun_RemoteErrorCarriesExitStatus(t *testing.T) {
	startTestSSHServer(t, false, false, true, 127)
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	writeTestKey(t, keyPath)

	p := testProbe("127.0.0.1")
	p.Key = keyPath
	_, err := Run(context.Background(), p, []string{"nc", "-z", "-w", "3", "10.0.40.1", "80"}, true)
	var remoteErr *RemoteError
	if !errors.As(err, &remoteErr) {
		t.Fatalf("expected *RemoteError, got %T: %v", err, err)
	}
	if remoteErr.Status() != 127 {
		t.Errorf("RemoteError.Status() = %d, want 127", remoteErr.Status())
	}
}

func TestRun_ExecRequestDenied(t *testing.T) {
	startTestSSHServer(t, false, false, false, 0)
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	writeTestKey(t, keyPath)

	p := testProbe("127.0.0.1")
	p.Key = keyPath
	if _, err := Run(context.Background(), p, []string{"echo", "hi"}, true); err == nil {
		t.Fatal("expected exec denial error")
	}
}

func TestRun_SessionRejected(t *testing.T) {
	startTestSSHServer(t, false, true, true, 0)
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	writeTestKey(t, keyPath)

	p := testProbe("127.0.0.1")
	p.Key = keyPath
	_, err := Run(context.Background(), p, []string{"echo", "hi"}, true)
	if err == nil {
		t.Fatal("expected session creation failure")
	}
	if !strings.Contains(err.Error(), "failed to create SSH session") {
		t.Errorf("error = %v", err)
	}
}

func TestCheck_Reachable(t *testing.T) {
	startTestSSHServer(t, false, false, true, 0)
	if err := Check(context.Background(), testProbe("127.0.0.1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckUnreachable(t *testing.T) {
	// RFC5737 non-routable address — should fail
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	p := Probe{
		Name: "test",
		Host: "192.0.2.1",
		User: "testuser",
		VLAN: "test",
	}
	err := Check(ctx, p)
	if err == nil {
		t.Fatal("expected error for unreachable host")
	}
}

func TestRunUnreachable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	p := Probe{
		Name: "test",
		Host: "192.0.2.1",
		User: "testuser",
		VLAN: "iot",
	}
	_, err := Run(ctx, p, []string{"echo", "hello"}, false)
	if err == nil {
		t.Fatal("expected error for unreachable host")
	}
	if !strings.Contains(err.Error(), `probe "test"`) {
		t.Errorf("error should mention probe name, got: %v", err)
	}
}

func TestShellQuote(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"simple", "'simple'"},
		{"with space", "'with space'"},
		{"has'quote", "'has'\\''quote'"},
		{"", "''"},
		{"multiple'quotes'here", "'multiple'\\''quotes'\\''here'"},
		{"$dollar `backtick`", "'$dollar `backtick`'"},
	}
	for _, tt := range tests {
		if got := shellQuote(tt.in); got != tt.want {
			t.Errorf("shellQuote(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestIsUnreachable(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{name: "transport", err: &TransportError{fmt.Errorf("dial failed")}, want: true},
		{name: "host key", err: &HostKeyError{fmt.Errorf("host key verification failed")}, want: true},
		{name: "auth", err: &AuthError{fmt.Errorf("unable to authenticate")}, want: true},
		{name: "remote command failure", err: &RemoteError{err: fmt.Errorf("exit status 1")}, want: false},
		{name: "generic", err: fmt.Errorf("something else"), want: false},
		{name: "nil", err: nil, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsUnreachable(tt.err); got != tt.want {
				t.Errorf("IsUnreachable(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

func TestUnreachableError_UsesConfiguredPort(t *testing.T) {
	// The unreachable error must name the probe's configured port, not a
	// hardcoded :22.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p := Probe{Name: "test", Host: "192.0.2.1", User: "testuser", VLAN: "iot", Port: 8022}
	_, err := Run(ctx, p, []string{"echo", "hello"}, false)
	if err == nil {
		t.Fatal("expected error for unreachable host")
	}
	var transErr *TransportError
	if !errors.As(err, &transErr) {
		t.Fatalf("expected *TransportError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "192.0.2.1:8022") {
		t.Errorf("error should mention configured port 8022, got: %v", err)
	}
	if strings.Contains(err.Error(), "192.0.2.1:22") {
		t.Errorf("error should not hardcode port 22, got: %v", err)
	}
}

func TestDialWithContext_CancellationAbortsDial(t *testing.T) {
	// A cancelled context must abort the dial promptly instead of waiting
	// out the default timeout.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	start := time.Now()
	_, err := dialWithContext(ctx, testProbe("192.0.2.1"))
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("expected cancelled context to abort the dial promptly, took %v", elapsed)
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got: %v", err)
	}
}
func TestDialWithContext_DefaultDeadline(t *testing.T) { // RFC5737 TEST-NET is non-routable: the dial hangs and must hit the
	// 10s default deadline imposed on a context without one.
	start := time.Now()
	_, err := dialWithContext(context.Background(), testProbe("192.0.2.1"))
	if err == nil {
		t.Fatal("expected dial failure for non-routable TEST-NET address")
	}
	// The ~10s elapsed proves the default deadline was applied, rather
	// than an instant failure.
	if elapsed := time.Since(start); elapsed < 8*time.Second || elapsed > 30*time.Second {
		t.Errorf("expected ~10s default deadline, took %v", time.Since(start))
	}
}

func TestDialWithContext_ExpiredDeadline(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	_, err := dialWithContext(ctx, testProbe("127.0.0.1"))
	if err == nil {
		t.Fatal("expected deadline exceeded error")
	}
	if !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Errorf("error = %v", err)
	}
}

func TestAuthMethods_KeyFromFile(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	writeTestKey(t, keyPath)
	t.Setenv("SSH_AUTH_SOCK", "")

	methods, agentConn, err := authMethods(keyPath)
	if agentConn != nil {
		agentConn.Close()
	}
	if err != nil {
		t.Fatalf("unexpected error for valid key: %v", err)
	}
	if len(methods) != 1 {
		t.Fatalf("expected 1 key method, got %d", len(methods))
	}
}

func TestAuthMethods_TildeExpansion(t *testing.T) {
	home := t.TempDir()
	t.Setenv("SSH_AUTH_SOCK", "")
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	} else {
		t.Setenv("HOME", home)
	}
	keyPath := filepath.Join(home, ".ssh", "id_ed25519")
	// 0o700 is the minimum usable directory mode (owner execute bit); the
	// pattern's 0600 ceiling applies to files, not directories.
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil { // nosemgrep: go.lang.correctness.permissions.file_permission.incorrect-default-permission
		t.Fatal(err)
	}
	writeTestKey(t, keyPath)

	methods, agentConn, err := authMethods("~/.ssh/id_ed25519")
	if agentConn != nil {
		agentConn.Close()
	}
	if err != nil {
		t.Fatalf("unexpected error for tilde-expanded key: %v", err)
	}
	if len(methods) != 1 {
		t.Fatalf("expected 1 key method via ~ expansion, got %d", len(methods))
	}
}

func TestAuthMethods_InvalidKeyFile(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyPath, []byte("not a private key"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSH_AUTH_SOCK", "")

	if _, _, err := authMethods(keyPath); err == nil {
		t.Fatal("expected error for unparsable key file")
	}
}

func TestAuthMethods_MissingKeyFile(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	if _, _, err := authMethods(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected error for missing key file")
	}
}

func TestAuthMethods_EmptyKeyPath(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	methods, agentConn, err := authMethods("")
	if agentConn != nil {
		agentConn.Close()
	}
	if err != nil {
		t.Fatalf("unexpected error without key: %v", err)
	}
	if len(methods) != 0 {
		t.Fatalf("expected 0 methods without key, got %d", len(methods))
	}
}

func TestConnectAgent_NoSocket(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	if conn := connectAgent(); conn != nil {
		conn.Close()
		t.Fatal("expected nil without SSH_AUTH_SOCK")
	}
}

func TestConnectAgent_UnreachableSocket(t *testing.T) {
	// The named-pipe dial on Windows and the unix-socket dial elsewhere both
	// fail fast for a nonexistent agent socket, so no platform skip needed.
	socket := `\\.\pipe\nyx-agent-missing`
	if runtime.GOOS != "windows" {
		socket = filepath.Join(t.TempDir(), "agent.sock")
	}
	t.Setenv("SSH_AUTH_SOCK", socket)
	if conn := connectAgent(); conn != nil {
		conn.Close()
		t.Fatal("expected nil for missing socket")
	}
}

func TestConnectAgent_AvailableSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets unavailable on Windows")
	}
	sockPath := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Skipf("cannot create unix socket: %v", err)
	}
	defer ln.Close()
	t.Setenv("SSH_AUTH_SOCK", sockPath)

	conn := connectAgent()
	if conn == nil {
		t.Fatal("expected agent connection")
	}
	defer conn.Close()
}

func TestAuthMethods_WithAgent(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix sockets unavailable on Windows")
	}
	sockPath := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Skipf("cannot create unix socket: %v", err)
	}
	defer ln.Close()
	t.Setenv("SSH_AUTH_SOCK", sockPath)
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	writeTestKey(t, keyPath)

	methods, agentConn, err := authMethods(keyPath)
	if agentConn == nil {
		t.Fatal("expected agent connection")
	}
	defer agentConn.Close()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(methods) != 2 {
		t.Fatalf("expected key + agent methods, got %d", len(methods))
	}
}

func TestRun_CancellationAbortsHangingCommand(t *testing.T) {
	// The remote server never replies to exec — the command hangs. The
	// context deadline must abort it by closing the connection.
	startTestSSHServer(t, true, false, false, 0)
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	writeTestKey(t, keyPath)

	p := testProbe("127.0.0.1")
	p.Key = keyPath

	ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := Run(ctx, p, []string{"sleep", "999"}, true)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("expected ctx cancellation to abort the hanging command quickly, took %v", elapsed)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected a context deadline error, got: %v", err)
	}
}

func TestRun_RemoteErrorTyped(t *testing.T) {
	startTestSSHServer(t, false, false, true, 3)
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	writeTestKey(t, keyPath)

	p := testProbe("127.0.0.1")
	p.Key = keyPath
	_, err := Run(context.Background(), p, []string{"false"}, true)
	if err == nil {
		t.Fatal("expected remote error")
	}
	var remoteErr *RemoteError
	if !errors.As(err, &remoteErr) {
		t.Fatalf("expected *RemoteError, got %T: %v", err, err)
	}
}

func TestRun_TransportErrorTyped(t *testing.T) {
	// An unreachable host yields a transport error, not remote or auth.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p := Probe{Name: "test", Host: "192.0.2.1", User: "u", VLAN: "iot"}
	_, err := Run(ctx, p, []string{"echo", "hi"}, true)
	if err == nil {
		t.Fatal("expected transport failure")
	}
	var transErr *TransportError
	if !errors.As(err, &transErr) {
		t.Fatalf("expected *TransportError, got %T: %v", err, err)
	}
}

func TestRun_AuthMethodsError(t *testing.T) {
	// An unreadable key must fail with the key detail after a successful
	// dial — Run must surface it rather than hand an empty method chain
	// to the SSH handshake.
	startTestSSHServer(t, false, false, true, 0)
	t.Setenv("SSH_AUTH_SOCK", "")
	p := testProbe("127.0.0.1")
	p.Key = filepath.Join(t.TempDir(), "missing-key")

	_, err := Run(context.Background(), p, []string{"echo", "hi"}, true)
	if err == nil {
		t.Fatal("expected error for unreadable key")
	}
	if !strings.Contains(err.Error(), "reading key file") {
		t.Errorf("expected key-reading detail in error, got: %v", err)
	}
}

// TestRun_AuthDiagnosticsTable covers the classified auth/host-key error
// paths table-driven: host-key failure, skip-verify success, key rejection,
// missing/unparsable key files, and a missing ssh-agent.
func TestRun_AuthDiagnosticsTable(t *testing.T) {
	tests := []struct {
		name        string
		setup       func(t *testing.T, srv *fake.Server) string // returns key path; "" = none
		skipVerify  bool
		rejectKeys  bool         // server rejects every public key
		wantErrKind reflect.Type // nil = success
		wantMessage string
	}{
		{
			name: "host key fail",
			setup: func(t *testing.T, _ *fake.Server) string {
				keyPath := filepath.Join(t.TempDir(), "id_ed25519")
				writeTestKey(t, keyPath)
				return keyPath
			},
			wantErrKind: reflect.TypeOf((*HostKeyError)(nil)),
			wantMessage: "host key verification failed",
		},
		{
			name: "skip verify succeeds",
			setup: func(t *testing.T, _ *fake.Server) string {
				keyPath := filepath.Join(t.TempDir(), "id_ed25519")
				writeTestKey(t, keyPath)
				return keyPath
			},
			skipVerify: true,
		},
		{
			name: "key rejected by server",
			setup: func(t *testing.T, _ *fake.Server) string {
				keyPath := filepath.Join(t.TempDir(), "id_ed25519")
				writeTestKey(t, keyPath)
				return keyPath
			},
			skipVerify:  true,
			rejectKeys:  true,
			wantErrKind: reflect.TypeOf((*AuthError)(nil)),
			wantMessage: "authentication failed",
		},
		{
			name: "missing key path",
			setup: func(t *testing.T, _ *fake.Server) string {
				return filepath.Join(t.TempDir(), "missing-key")
			},
			wantErrKind: reflect.TypeOf((*AuthError)(nil)),
			wantMessage: "reading key file",
		},
		{
			name: "unparsable key",
			setup: func(t *testing.T, _ *fake.Server) string {
				keyPath := filepath.Join(t.TempDir(), "id_ed25519")
				if err := os.WriteFile(keyPath, []byte("not a private key"), 0o600); err != nil {
					t.Fatal(err)
				}
				return keyPath
			},
			wantErrKind: reflect.TypeOf((*AuthError)(nil)),
			wantMessage: "parsing key file",
		},
		{
			name: "no key and no agent",
			setup: func(t *testing.T, _ *fake.Server) string {
				t.Setenv("SSH_AUTH_SOCK", "")
				return ""
			},
			wantErrKind: reflect.TypeOf((*AuthError)(nil)),
			wantMessage: "no authentication methods available",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withTestHome(t)
			if tt.rejectKeys {
				startTestSSHServerRejectingKeys(t, false, false, true, 0)
			} else {
				startTestSSHServer(t, false, false, true, 0)
			}
			p := testProbe("127.0.0.1")
			p.Key = tt.setup(t, nil)

			_, err := Run(context.Background(), p, []string{"echo", "hi"}, tt.skipVerify)
			if tt.wantErrKind == nil {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatal("expected error")
			}
			target := reflect.New(tt.wantErrKind).Interface()
			if !errors.As(err, target) {
				t.Fatalf("expected %v, got %T: %v", tt.wantErrKind, err, err)
			}
			if !strings.Contains(err.Error(), tt.wantMessage) {
				t.Errorf("error should contain %q, got: %v", tt.wantMessage, err)
			}
		})
	}
}

func TestDiagnose_HostKeyFailure(t *testing.T) {
	startTestSSHServer(t, false, false, true, 0)
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	writeTestKey(t, keyPath)
	withTestHome(t)

	p := testProbe("127.0.0.1")
	p.Key = keyPath
	err := Diagnose(context.Background(), p)
	var hostKeyErr *HostKeyError
	if !errors.As(err, &hostKeyErr) {
		t.Fatalf("expected *HostKeyError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "skip_host_key_verify") {
		t.Errorf("error should mention skip_host_key_verify, got: %v", err)
	}
}

func TestRun_NonSSHServerDefaultsToTransportError(t *testing.T) {
	// A host that accepts TCP but never speaks SSH fails the handshake with
	// an unclassifiable error, which must surface as a TransportError.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()

	p := testProbe("127.0.0.1")
	p.Port = ln.Addr().(*net.TCPAddr).Port
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	writeTestKey(t, keyPath)
	p.Key = keyPath
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err = Run(ctx, p, []string{"echo", "ok"}, true)
	var transportErr *TransportError
	if !errors.As(err, &transportErr) {
		t.Fatalf("expected *TransportError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "unreachable") {
		t.Errorf("error should be actionable, got: %v", err)
	}
}

func TestDiagnose_SpecSkipFlagHonored(t *testing.T) {
	// A probe configured with skip_host_key_verify reaches the auth phase,
	// so a valid key succeeds end-to-end.
	startTestSSHServer(t, false, false, true, 0)
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	writeTestKey(t, keyPath)

	p := testProbe("127.0.0.1")
	p.Key = keyPath
	p.SkipHostKeyVerify = true
	if err := Diagnose(context.Background(), p); err != nil {
		t.Fatalf("unexpected error with spec-level skip: %v", err)
	}
}

func TestDiagnose_AuthFailure(t *testing.T) {
	// With host-key verification on, the handshake dies at the host-key
	// check before auth runs; a probe that skips verification surfaces the
	// auth failure instead.
	startTestSSHServerRejectingKeys(t, false, false, true, 0)
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	writeTestKey(t, keyPath)

	p := testProbe("127.0.0.1")
	p.Key = keyPath
	p.SkipHostKeyVerify = true
	err := Diagnose(context.Background(), p)
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected *AuthError, got %T: %v", err, err)
	}
	if !strings.Contains(err.Error(), "SSH_AUTH_SOCK") {
		t.Errorf("error should mention SSH_AUTH_SOCK guidance, got: %v", err)
	}
}

func TestAuthError_UsesConfiguredPort(t *testing.T) {
	// The auth-failure error must name the probe's configured port, not a
	// hardcoded :22.
	startTestSSHServerRejectingKeys(t, false, false, true, 0)
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	writeTestKey(t, keyPath)

	p := testProbe("127.0.0.1")
	p.Key = keyPath
	p.SkipHostKeyVerify = true
	_, err := Run(context.Background(), p, []string{"echo", "hi"}, true)
	var authErr *AuthError
	if !errors.As(err, &authErr) {
		t.Fatalf("expected *AuthError, got %T: %v", err, err)
	}
	want := fmt.Sprintf("at 127.0.0.1:%d", lastTestServerPort)
	if !strings.Contains(err.Error(), want) {
		t.Errorf("error should mention configured port %d, got: %v", lastTestServerPort, err)
	}
}

func TestDiagnose_Unreachable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p := Probe{Name: "test", Host: "192.0.2.1", User: "u", VLAN: "iot"}
	err := Diagnose(ctx, p)
	var transErr *TransportError
	if !errors.As(err, &transErr) {
		t.Fatalf("expected *TransportError, got %T: %v", err, err)
	}
}

func TestFromSpec(t *testing.T) {
	got := FromSpec(intent.Probe{Name: "p", Host: "1.2.3.4", User: "u", Port: 2222, Key: "k", VLAN: "iot", SkipHostKeyVerify: true})
	want := Probe{Name: "p", Host: "1.2.3.4", User: "u", Port: 2222, Key: "k", VLAN: "iot", SkipHostKeyVerify: true}
	if got != want {
		t.Errorf("FromSpec = %+v, want %+v", got, want)
	}
}

// TestDiagnosticCheckTable exercises the doctor-shaped check across the
// classified outcomes: pass, host-key failure, auth failure, unreachable.
func TestDiagnosticCheckTable(t *testing.T) {
	tests := []struct {
		name         string
		setup        func(t *testing.T) Probe
		wantStatus   models.Status
		wantReached  bool
		wantAuthOK   bool
		wantViolates bool
	}{
		{
			name: "pass",
			setup: func(t *testing.T) Probe {
				startTestSSHServer(t, false, false, true, 0)
				keyPath := filepath.Join(t.TempDir(), "id_ed25519")
				writeTestKey(t, keyPath)
				p := testProbe("127.0.0.1")
				p.Key = keyPath
				p.SkipHostKeyVerify = true
				return p
			},
			wantStatus: models.StatusPass, wantReached: true, wantAuthOK: true,
		},
		{
			name: "host key fail",
			setup: func(t *testing.T) Probe {
				startTestSSHServer(t, false, false, true, 0)
				keyPath := filepath.Join(t.TempDir(), "id_ed25519")
				writeTestKey(t, keyPath)
				p := testProbe("127.0.0.1")
				p.Key = keyPath
				return p
			},
			wantStatus: models.StatusFail, wantReached: true, wantAuthOK: false, wantViolates: true,
		},
		{
			name: "auth fail",
			setup: func(t *testing.T) Probe {
				startTestSSHServerRejectingKeys(t, false, false, true, 0)
				keyPath := filepath.Join(t.TempDir(), "id_ed25519")
				writeTestKey(t, keyPath)
				p := testProbe("127.0.0.1")
				p.Key = keyPath
				p.SkipHostKeyVerify = true
				return p
			},
			wantStatus: models.StatusFail, wantReached: true, wantAuthOK: false, wantViolates: true,
		},
		{
			name: "unreachable",
			setup: func(t *testing.T) Probe {
				return Probe{Name: "test", Host: "192.0.2.1", User: "u", VLAN: "iot"}
			},
			wantStatus: models.StatusFail, wantReached: false, wantAuthOK: false, wantViolates: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			withTestHome(t)
			p := tt.setup(t)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			c := DiagnosticCheck(ctx, p)
			if c.Status != tt.wantStatus {
				t.Errorf("status = %q, want %q", c.Status, tt.wantStatus)
			}
			if got, _ := c.Observed["reachable"].(bool); got != tt.wantReached {
				t.Errorf("observed reachable = %v, want %v", c.Observed["reachable"], tt.wantReached)
			}
			if got, _ := c.Observed["auth_ok"].(bool); got != tt.wantAuthOK {
				t.Errorf("observed auth_ok = %v, want %v", c.Observed["auth_ok"], tt.wantAuthOK)
			}
			if (len(c.Violations) > 0) != tt.wantViolates {
				t.Errorf("violations = %v, wantViolates = %v", c.Violations, tt.wantViolates)
			}
		})
	}
}

// TestDiagnose_HandshakeStallHonorsContextDeadline reproduces #167: a peer
// that accepts TCP but never completes the SSH handshake must not block
// past the context deadline. The listener accepts the connection and holds
// it open without sending any SSH banner; Diagnose must return within the
// deadline with a transport error.
func TestDiagnose_HandshakeStallHonorsContextDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	stalled := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		// Hold the connection open without sending the SSH banner.
		stalled <- conn
	}()

	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	writeTestKey(t, keyPath)
	p := Probe{Name: "iot-probe", Host: "127.0.0.1", User: "testuser", VLAN: "iot", Port: ln.Addr().(*net.TCPAddr).Port, Key: keyPath}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	err = Diagnose(ctx, p)
	elapsed := time.Since(start)

	if conn := <-stalled; conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatal("Diagnose against a stalling handshake should fail")
	}
	var transport *TransportError
	if !errors.As(err, &transport) {
		t.Errorf("error = %v, want TransportError", err)
	}
	if elapsed > 300*time.Millisecond {
		t.Errorf("Diagnose returned after %v, want it bounded near the 50ms deadline", elapsed)
	}
}

// TestRun_HandshakeStallHonorsContextDeadline pins the same contract for
// Run: a stalled handshake is interrupted by the context deadline instead
// of hanging until the remote side closes the socket.
func TestRun_HandshakeStallHonorsContextDeadline(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	stalled := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		stalled <- conn
	}()

	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	writeTestKey(t, keyPath)
	p := Probe{Name: "iot-probe", Host: "127.0.0.1", User: "testuser", VLAN: "iot", Port: ln.Addr().(*net.TCPAddr).Port, Key: keyPath}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = Run(ctx, p, []string{"echo", "hi"}, true)
	elapsed := time.Since(start)

	if conn := <-stalled; conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatal("Run against a stalling handshake should fail")
	}
	if elapsed > 300*time.Millisecond {
		t.Errorf("Run returned after %v, want it bounded near the 50ms deadline", elapsed)
	}
}

// TestRun_CancellationWithoutDeadlineAbortsHandshake pins the watcher
// branch: with no deadline on the context, the raw connection's 10s
// handshake cap cannot be waited out — only the cancellation watcher can
// unblock a stalled handshake, and it must.
func TestRun_CancellationWithoutDeadlineAbortsHandshake(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	stalled := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		stalled <- conn
	}()

	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	writeTestKey(t, keyPath)
	p := Probe{Name: "iot-probe", Host: "127.0.0.1", User: "testuser", VLAN: "iot", Port: ln.Addr().(*net.TCPAddr).Port, Key: keyPath}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	_, err = Run(ctx, p, []string{"echo", "hi"}, true)
	elapsed := time.Since(start)

	if conn := <-stalled; conn != nil {
		conn.Close()
	}
	if err == nil {
		t.Fatal("a canceled handshake must fail")
	}
	if elapsed > 300*time.Millisecond {
		t.Errorf("Run returned after %v, want the cancellation to abort the stalled handshake near 50ms", elapsed)
	}
}
