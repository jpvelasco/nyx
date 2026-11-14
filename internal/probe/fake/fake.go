// Package fake provides an in-process SSH server for tests of the probe
// client. It binds an ephemeral 127.0.0.1 port (privileged port 22 is
// avoided so these tests also run on rootless CI runners) and serves a real
// SSH handshake, so dial, authentication, and exec paths are exercised
// without external dependencies or live network scans.
package fake

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// TestCredential is the single password the server's password callback
// accepts. Probe clients authenticate with public keys in tests, so this
// only exercises the rejection path of the handshake.
const TestCredential = "testpass"

// Options configures the behavior of a fake SSH server.
type Options struct {
	// HangExec makes exec requests hang forever (no reply, no close),
	// simulating a remote command that runs past the caller's deadline.
	HangExec bool
	// RejectSessions rejects every session channel.
	RejectSessions bool
	// ExecReply replies accept to exec requests; when false the request is
	// rejected.
	ExecReply bool
	// RejectKeys rejects every public key, exercising client-side
	// authentication failures without racing a config mutation against the
	// serve goroutine.
	RejectKeys bool
	// ExitStatus is the exit status reported for exec requests when OnExec
	// is nil.
	ExitStatus uint32
	// OnExec, when set, decides the output and exit status per command,
	// replacing the fixed ExitStatus behavior.
	OnExec func(cmd string) (output string, exitStatus uint32)
}

// Server is a running fake SSH server on an ephemeral loopback port.
type Server struct {
	ln     net.Listener
	config *ssh.ServerConfig
	opts   Options
	Port   int
	wg     sync.WaitGroup
}

// Start binds an ephemeral 127.0.0.1 port and serves SSH in the background.
// t.Cleanup closes the listener and waits for the serve loop.
func Start(t *testing.T, opts Options) *Server {
	t.Helper()
	hostKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyCallback := func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		return nil, nil
	}
	if opts.RejectKeys {
		publicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			return nil, fmt.Errorf("key rejected for %q", conn.User())
		}
	}
	config := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if subtle.ConstantTimeCompare(password, []byte(TestCredential)) == 1 {
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", conn.User())
		},
		PublicKeyCallback: publicKeyCallback,
	}
	config.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cannot bind fake SSH listener: %v", err)
	}
	srv := &Server{ln: ln, config: config, opts: opts, Port: ln.Addr().(*net.TCPAddr).Port}
	srv.wg.Add(1)
	go srv.serve()
	// Cleanup runs LIFO: close the listener first, then wait for the serve loop.
	t.Cleanup(srv.wg.Wait)
	t.Cleanup(func() {
		if err := ln.Close(); err != nil {
			t.Logf("closing fake SSH listener: %v", err)
		}
	})
	return srv
}

func (s *Server) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(conn)
	}
}

func (s *Server) handleConn(conn net.Conn) {
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.config)
	if err != nil {
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)
	for newChannel := range chans {
		if newChannel.ChannelType() != "session" {
			// A failed reject means the connection is already broken; stop
			// serving it.
			if err := newChannel.Reject(ssh.UnknownChannelType, "unsupported channel"); err != nil {
				return
			}
			continue
		}
		if s.opts.RejectSessions {
			if err := newChannel.Reject(ssh.UnknownChannelType, "sessions disabled"); err != nil {
				return
			}
			continue
		}
		ch, requests, err := newChannel.Accept()
		if err != nil {
			continue
		}
		go s.handleSession(ch, requests)
	}
}

func (s *Server) handleSession(ch ssh.Channel, requests <-chan *ssh.Request) {
	defer ch.Close()
	for req := range requests {
		if req.Type != "exec" {
			continue
		}
		if s.opts.HangExec {
			// Never reply or close — the remote command "runs" forever.
			continue
		}
		if !s.opts.ExecReply {
			// A failed reply means the connection is already broken; the
			// rejected exec ends the session handler either way.
			if err := req.Reply(false, nil); err != nil {
				return
			}
			return
		}
		if err := req.Reply(true, nil); err != nil {
			return
		}
		cmd := CommandFromExecPayload(req.Payload)
		output := cmd
		status := s.opts.ExitStatus
		if s.opts.OnExec != nil {
			output, status = s.opts.OnExec(cmd)
		}
		if _, err := ch.Write([]byte(output)); err != nil {
			return
		}
		if _, err := ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: status})); err != nil {
			return
		}
		return
	}
}

// CommandFromExecPayload extracts the command string from an RFC4254 exec request.
func CommandFromExecPayload(payload []byte) string {
	if len(payload) < 4 {
		return ""
	}
	size := binary.BigEndian.Uint32(payload[:4])
	if int(size) > len(payload)-4 {
		return string(payload[4:])
	}
	return string(payload[4 : 4+size])
}

// WriteKey writes a fresh ed25519 private key in OpenSSH format to path.
func WriteKey(t *testing.T, path string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "") // #nosec G505 — throwaway test key with no passphrase
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
}
