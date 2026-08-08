// Package probe implements remote execution of certain assertions over SSH from declared probe hosts (for multi-VLAN vantage points).
package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// TransportError indicates the probe itself could not be reached,
// authenticated, or handed a session — the remote command never ran.
// Callers must distinguish this from a remote command that ran and
// failed (see RemoteError).
type TransportError struct{ err error }

func (e *TransportError) Error() string { return e.err.Error() }
func (e *TransportError) Unwrap() error { return e.err }

// RemoteError indicates the remote command executed but exited non-zero
// (e.g. nc -z on a closed port, or ping with 100% packet loss).
type RemoteError struct{ err error }

func (e *RemoteError) Error() string { return e.err.Error() }
func (e *RemoteError) Unwrap() error { return e.err }

// Probe represents a remote node that can execute commands via SSH.
type Probe struct {
	Name              string // probe name
	Host              string // IP or hostname
	User              string // SSH username
	Port              int    // SSH port; 0 means 22
	Key               string // path to private key; empty = ssh-agent only
	VLAN              string // informational label
	SkipHostKeyVerify bool   // skip SSH host key verification (like ssh -o StrictHostKeyChecking=no)
}

// addr returns the host:port endpoint, defaulting to port 22.
func (p Probe) addr() string {
	port := p.Port
	if port == 0 {
		port = 22
	}
	return fmt.Sprintf("%s:%d", p.Host, port)
}

// Run executes a command on the probe and returns combined stdout+stderr output.
// When skipHostKeyVerify is true, SSH host key verification is bypassed (like ssh -o StrictHostKeyChecking=no).
// When false (default), the probe's own SkipHostKeyVerify setting is honored.
// Each argument is shell-quoted before joining so args with spaces or special
// characters are preserved across the SSH shell boundary.
// On dial failure, returns a descriptive error mentioning the probe name, host, and VLAN.
func Run(ctx context.Context, p Probe, cmd []string, skipHostKeyVerify bool) (string, error) {
	conn, err := dialWithContext(ctx, p)
	if err != nil {
		return "", &TransportError{fmt.Errorf("probe %q unreachable at %s:22 — is the host on VLAN %s and SSH running? (%w)", p.Name, p.Host, p.VLAN, err)}
	}
	defer conn.Close()

	// The SSH session itself has no context binding, so a cancelled or
	// expired context (e.g. the per-assertion timeout) must abort an
	// in-flight remote command by closing the connection.
	abort := make(chan struct{})
	defer close(abort)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close() // #nosec G104 — best-effort abort of a hung remote command
		case <-abort:
		}
	}()

	// Build auth methods; agentConn (if any) must stay open until the session ends.
	methods, agentConn, err := authMethods(p.Key)
	if agentConn != nil {
		defer agentConn.Close()
	}
	if err != nil {
		return "", fmt.Errorf("probe %q: %w", p.Name, err)
	}
	if len(methods) == 0 {
		return "", fmt.Errorf("probe %q: no authentication methods available", p.Name)
	}

	hostKeyCallback := ssh.HostKeyCallback(func(hostname string, _ net.Addr, _ ssh.PublicKey) error {
		return fmt.Errorf("probe %q: host key verification failed for %s — use --skip-host-key-verify or set skip_host_key_verify: true in probe spec", p.Name, hostname)
	})
	if skipHostKeyVerify || p.SkipHostKeyVerify {
		hostKeyCallback = ssh.InsecureIgnoreHostKey() // #nosec G106 — user explicitly opted out // nosemgrep codacy.tools-configs.go.lang.security.audit.crypto.insecure_ssh.avoid-ssh-insecure-ignore-host-key codacy.tools-configs.go_crypto_rule-insecure-ignore-host-key
	}

	cfg := &ssh.ClientConfig{
		User:            p.User,
		Auth:            methods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, p.addr(), cfg)
	if err != nil {
		return "", &TransportError{fmt.Errorf("probe %q unreachable at %s:22 — is the host on VLAN %s and SSH running? (%w)", p.Name, p.Host, p.VLAN, err)}
	}
	defer sshConn.Close()

	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", &TransportError{fmt.Errorf("probe %q: failed to create SSH session: %w", p.Name, err)}
	}
	defer session.Close()

	// Shell-quote each argument so args with spaces/special chars survive the
	// remote shell boundary without being interpreted.
	quoted := make([]string, len(cmd))
	for i, arg := range cmd {
		quoted[i] = shellQuote(arg)
	}
	output, err := session.CombinedOutput(strings.Join(quoted, " "))
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return string(output), ctxErr
		}
		var exitErr *ssh.ExitError
		if errors.As(err, &exitErr) {
			//nolint:staticcheck // SA1019 — ExitError.Waitmsg is deprecated; status is what callers need
			return string(output), &RemoteError{fmt.Errorf("remote command failed with status %d: %w", exitErr.ExitStatus(), err)}
		}
		return string(output), err
	}
	return string(output), nil
}

// shellQuote wraps a string in single quotes, escaping any embedded single quotes.
// This is the POSIX-safe way to pass arbitrary values through a shell command line.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// Check verifies that the probe is reachable via TCP on port 22 (no SSH handshake).
func Check(ctx context.Context, p Probe) error {
	conn, err := dialWithContext(ctx, p)
	if err != nil {
		return err
	}
	conn.Close() // #nosec G104 — best-effort cleanup
	return nil
}

// dialWithContext establishes a TCP connection to p.Host:22 with the given context deadline.
func dialWithContext(ctx context.Context, p Probe) (net.Conn, error) {
	// Extract deadline from context
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(10 * time.Second)
	}
	timeout := time.Until(deadline)
	if timeout <= 0 {
		return nil, fmt.Errorf("context deadline exceeded")
	}

	return net.DialTimeout("tcp", p.addr(), timeout)
}

// authMethods builds the SSH auth method chain: private key (if provided) then ssh-agent.
// Returns the agent connection if one was opened — the caller must close it after the
// SSH session ends (closing it too early would break agent-based auth mid-handshake).
func authMethods(keyPath string) ([]ssh.AuthMethod, net.Conn, error) {
	var methods []ssh.AuthMethod

	if keyPath != "" {
		if strings.HasPrefix(keyPath, "~/") {
			home, err := os.UserHomeDir()
			if err == nil {
				// #nosec G304 — path from spec, resolves to home dir
				keyPath = filepath.Join(home, keyPath[2:]) // nosemgrep
			}
		}
		// #nosec G304 — path from spec, resolves to home dir
		keyBytes, err := os.ReadFile(keyPath) // nosemgrep
		if err != nil {
			return nil, nil, fmt.Errorf("reading key file: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(keyBytes)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing key file %s: %w", keyPath, err)
		}
		methods = append(methods, ssh.PublicKeys(signer))
	}

	agentConn := connectAgent()
	if agentConn != nil {
		agentClient := agent.NewClient(agentConn)
		methods = append(methods, ssh.PublicKeysCallback(agentClient.Signers))
	}

	return methods, agentConn, nil
}

// connectAgent attempts to connect to the SSH agent via SSH_AUTH_SOCK.
// Returns nil if unavailable. On Windows the socket is a named pipe.
func connectAgent() net.Conn {
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return nil
	}

	conn, err := dialAgent(socket)
	if err != nil {
		return nil
	}

	return conn
}
