package fake

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// pinnedConfig builds a client config that pins the fake server's host key,
// so every client connection exercises real host-key verification.
func pinnedConfig(srv *Server, auth ssh.AuthMethod) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User:            "testuser",
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.FixedHostKey(srv.HostKey()),
		Timeout:         5 * time.Second,
	}
}

// dialClient connects to the server with a single auth method. The client
// closes itself at test end.
func dialClient(t *testing.T, srv *Server, auth ssh.AuthMethod) *ssh.Client {
	t.Helper()
	client, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", srv.Port), pinnedConfig(srv, auth))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

// keySigner generates a throwaway ed25519 key in memory; the file-based
// parse path is covered by the probe package's authMethods tests.
func keySigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer
}

// The server closes the session channel after one exec, so every command
// gets a fresh session.
func runExec(t *testing.T, client *ssh.Client, cmd string) (string, error) {
	t.Helper()
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	out, err := sess.CombinedOutput(cmd)
	sess.Close()
	return string(out), err
}

// Default server: a key-authenticated exec echoes the command with exit 0.
func TestServerExecDefault(t *testing.T) {
	srv := Start(t, Options{ExecReply: true})
	client := dialClient(t, srv, ssh.PublicKeys(keySigner(t)))
	out, err := runExec(t, client, "echo hi")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if out != "echo hi" {
		t.Errorf("output = %q, want %q", out, "echo hi")
	}
}

// OnExec decides the output and exit status per command.
func TestServerExecOnExec(t *testing.T) {
	srv := Start(t, Options{
		ExecReply: true,
		OnExec: func(cmd string) (string, uint32) {
			if cmd == "fail" {
				return "boom", 3
			}
			return "ok-" + cmd, 0
		},
	})
	client := dialClient(t, srv, ssh.PublicKeys(keySigner(t)))

	out, err := runExec(t, client, "one")
	if err != nil {
		t.Fatalf("exec one: %v", err)
	}
	if out != "ok-one" {
		t.Errorf("output = %q, want %q", out, "ok-one")
	}

	out, err = runExec(t, client, "fail")
	var exitErr *ssh.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("expected *ssh.ExitError, got %v", err)
	}
	if exitErr.ExitStatus() != 3 {
		t.Errorf("exit status = %d, want 3", exitErr.ExitStatus())
	}
	if out != "boom" {
		t.Errorf("output = %q, want %q", out, "boom")
	}
}

// With ExecReply=false the exec request is rejected: the command errors.
func TestServerExecRejected(t *testing.T) {
	srv := Start(t, Options{ExecReply: false})
	client := dialClient(t, srv, ssh.PublicKeys(keySigner(t)))
	if _, err := runExec(t, client, "echo hi"); err == nil {
		t.Fatal("expected exec to be rejected, got success")
	}
}

// Requests other than exec are ignored by the session handler: they get
// no reply and the session stays usable.
func TestServerNonExecRequestIgnored(t *testing.T) {
	srv := Start(t, Options{ExecReply: true})
	client := dialClient(t, srv, ssh.PublicKeys(keySigner(t)))
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	if _, err := sess.SendRequest("shell", false, nil); err != nil {
		t.Fatalf("send shell request: %v", err)
	}
	sess.Close()
}

// RejectSessions: the handshake succeeds but session channels are rejected.
func TestServerRejectSessions(t *testing.T) {
	srv := Start(t, Options{RejectSessions: true})
	client := dialClient(t, srv, ssh.PublicKeys(keySigner(t)))
	if _, err := client.NewSession(); err == nil {
		t.Fatal("expected the session channel to be rejected")
	}
}

// Unknown channel types are rejected instead of silently dropped.
func TestServerUnknownChannelRejected(t *testing.T) {
	srv := Start(t, Options{ExecReply: true})
	client := dialClient(t, srv, ssh.PublicKeys(keySigner(t)))
	ch, _, err := client.OpenChannel("no-such-channel", nil)
	if err == nil {
		ch.Close()
		t.Fatal("expected the unknown channel to be rejected")
	}
}

// HangExec never replies to the exec request: the command stays pending
// instead of returning, so the test bounds the wait and then drops the
// session.
func TestServerHangExec(t *testing.T) {
	srv := Start(t, Options{HangExec: true})
	client := dialClient(t, srv, ssh.PublicKeys(keySigner(t)))
	sess, err := client.NewSession()
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- sess.Run("sleep 60") }()
	select {
	case err := <-done:
		t.Fatalf("exec returned before the deadline: %v", err)
	case <-time.After(500 * time.Millisecond):
	}
	sess.Close() // unblock the pending Run
	<-done
}

// RejectKeys: a public-key client cannot authenticate.
func TestServerRejectKeys(t *testing.T) {
	srv := Start(t, Options{RejectKeys: true})
	client, err := ssh.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", srv.Port), pinnedConfig(srv, ssh.PublicKeys(keySigner(t))))
	if err == nil {
		client.Close()
		t.Fatal("expected key auth to be rejected")
	}
}

// Password auth: the wrong password is refused, TestCredential is accepted.
func TestServerPasswordAuth(t *testing.T) {
	srv := Start(t, Options{ExecReply: true})
	addr := fmt.Sprintf("127.0.0.1:%d", srv.Port)
	if client, err := ssh.Dial("tcp", addr, pinnedConfig(srv, ssh.Password("wrong"))); err == nil {
		client.Close()
		t.Fatal("expected the wrong password to be rejected")
	}
	client, err := ssh.Dial("tcp", addr, pinnedConfig(srv, ssh.Password(TestCredential)))
	if err != nil {
		t.Fatalf("TestCredential should authenticate: %v", err)
	}
	client.Close()
}

// A connection that is not SSH dies inside the handshake; the serve loop
// keeps accepting afterwards.
func TestServerGarbageConnection(t *testing.T) {
	srv := Start(t, Options{ExecReply: true})
	raw, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", srv.Port))
	if err != nil {
		t.Fatalf("raw dial: %v", err)
	}
	raw.Write([]byte("not ssh\r\n"))
	raw.Close()

	client := dialClient(t, srv, ssh.PublicKeys(keySigner(t)))
	out, err := runExec(t, client, "echo hi")
	if err != nil {
		t.Fatalf("exec after the garbage connection: %v", err)
	}
	if out != "echo hi" {
		t.Errorf("output = %q, want %q", out, "echo hi")
	}
}
