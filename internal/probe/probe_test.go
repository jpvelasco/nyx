package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const testSSHPassword = "testpass"

// lastTestServerPort tracks the ephemeral port of the most recently started
// test SSH server so testProbe can point Run/Check at it. Tests start their
// server before building the probe, so the value is always the right one.
var lastTestServerPort int

// testSSHServer is an in-process SSH server used to exercise Run/Check
// against a real handshake on 127.0.0.1:22 without external dependencies.
type testSSHServer struct {
	t              *testing.T
	ln             net.Listener
	config         *ssh.ServerConfig
	rejectSessions bool
	hangExec       bool
	execReply      bool
	exitStatus     uint32
	wg             sync.WaitGroup
}

// startTestSSHServer binds an ephemeral loopback port and serves SSH in the
// background. The bound port is recorded in lastTestServerPort so testProbe
// points Run/Check at the running server. Ephemeral ports avoid privileged
// port 22 so these tests also run on rootless CI runners.
func startTestSSHServer(t *testing.T, hangExec bool, rejectSessions bool, execReply bool, exitStatus uint32) *testSSHServer {
	t.Helper()
	hostKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if subtle.ConstantTimeCompare(password, []byte(testSSHPassword)) == 1 {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", conn.User())
		},
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, nil
		},
	}
	config.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot bind test SSH listener: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	lastTestServerPort = port

	srv := &testSSHServer{t: t, ln: ln, config: config, hangExec: hangExec, rejectSessions: rejectSessions, execReply: execReply, exitStatus: exitStatus}
	srv.wg.Add(1)
	go srv.serve()
	// Cleanup runs LIFO: close the listener first, then wait for the serve loop.
	t.Cleanup(srv.wg.Wait)
	t.Cleanup(func() { ln.Close() })
	return srv
}

func (s *testSSHServer) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *testSSHServer) handleConn(conn net.Conn) {
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.config)
	if err != nil {
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unsupported channel")
			continue
		}
		if s.rejectSessions {
			newChannel.Reject(ssh.UnknownChannelType, "sessions disabled")
			continue
		}
		ch, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		go s.handleSession(ch, requests)
	}
}

func (s *testSSHServer) handleSession(ch ssh.Channel, requests <-chan *ssh.Request) {
	defer ch.Close()
	for req := range requests {
		if req.Type != "exec" {
			continue
		}
		if s.hangExec {
			// Never reply or close — the remote command "runs" forever.
			continue
		}
		if !s.execReply {
			req.Reply(false, nil)
			return
		}
		req.Reply(true, nil)
		if _, err := ch.Write([]byte(commandFromExecPayload(req.Payload))); err != nil {
			return
		}
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: s.exitStatus}))
		return
	}
}

// commandFromExecPayload extracts the command string from an RFC4254 exec request.
func commandFromExecPayload(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	size := binary.BigEndian.Uint32(payload[:4])
	if int(size) > len(payload)-4 {
		return string(payload[4:])
	}
	return string(payload[4 : 4+size])
}

// writeTestKey writes a fresh ed25519 private key in OpenSSH format.
func writeTestKey(t *testing.T, path string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(block)
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
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

	p := testProbe("127.0.0.1")
	p.Key = keyPath
	_, err := Run(context.Background(), p, []string{"echo", "hi"}, false)
	if err == nil {
		t.Fatal("expected host key verification failure")
	}
	if !strings.Contains(err.Error(), `probe "p1" unreachable`) {
		t.Errorf("error should mention probe name, got: %v", err)
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

func TestDialWithContext_DefaultDeadline(t *testing.T) {
	// RFC5737 TEST-NET is non-routable: the dial hangs and must hit the
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
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
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

func TestCommandFromExecPayload(t *testing.T) {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, uint32(len("echo hi")))
	payload = append(payload, []byte("echo hi")...)
	if got := commandFromExecPayload(payload); got != "echo hi" {
		t.Errorf("got %q", got)
	}
	if got := commandFromExecPayload(nil); got != "" {
		t.Errorf("empty payload should give empty command, got %q", got)
	}
	if got := commandFromExecPayload([]byte{0, 0, 0, 99, 'a'}); got != "a" {
		t.Errorf("oversized length should fall back, got %q", got)
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
	// Host key verification fails → transport error, not remote error.
	startTestSSHServer(t, false, false, true, 0)
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	writeTestKey(t, keyPath)

	p := testProbe("127.0.0.1")
	p.Key = keyPath
	_, err := Run(context.Background(), p, []string{"echo", "hi"}, false)
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
