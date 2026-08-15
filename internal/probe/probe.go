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

	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
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

// HostKeyError indicates SSH host key verification failed; the connection
// was refused before authentication.
type HostKeyError struct{ err error }

func (e *HostKeyError) Error() string { return e.err.Error() }
func (e *HostKeyError) Unwrap() error { return e.err }

// AuthError indicates SSH authentication failed or no usable credentials
// (key file or ssh-agent) were available.
type AuthError struct{ err error }

func (e *AuthError) Error() string { return e.err.Error() }
func (e *AuthError) Unwrap() error { return e.err }

// IsUnreachable reports whether err means the probe never executed the
// remote command — transport, host-key, or authentication failure — as
// opposed to the command running and failing (RemoteError). Callers use
// this to avoid treating probe outages as remote evidence.
func IsUnreachable(err error) bool {
	var transErr *TransportError
	var hostKeyErr *HostKeyError
	var authErr *AuthError
	return errors.As(err, &transErr) || errors.As(err, &hostKeyErr) || errors.As(err, &authErr)
}

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
// Failures are typed: TransportError (unreachable), HostKeyError (untrusted
// host key), AuthError (bad credentials), RemoteError (command failed).
func Run(ctx context.Context, p Probe, cmd []string, skipHostKeyVerify bool) (string, error) {
	client, err := dialAndAuth(ctx, p, skipHostKeyVerify)
	if err != nil {
		return "", err
	}
	defer client.Close()

	// The SSH session itself has no context binding, so a cancelled or
	// expired context (e.g. the per-assertion timeout) must abort an
	// in-flight remote command by closing the connection.
	abort := make(chan struct{})
	defer close(abort)
	go func() {
		select {
		case <-ctx.Done():
			_ = client.Close() // #nosec G104 — best-effort abort of a hung remote command
		case <-abort:
		}
	}()

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

// dialAndAuth establishes a TCP connection and completes the SSH handshake.
// Handshake failures are classified into HostKeyError, AuthError, or
// TransportError with actionable guidance. On success the connection is
// owned by the returned ssh.Client; on failure it is closed here. The agent
// connection (if any) only needs to live for the handshake, where auth
// callbacks run.
func dialAndAuth(ctx context.Context, p Probe, skipHostKeyVerify bool) (*ssh.Client, error) {
	conn, err := dialWithContext(ctx, p)
	if err != nil {
		return nil, unreachableError(p, err)
	}

	// Build auth methods; agentConn (if any) must stay open until the handshake ends.
	methods, agentConn, err := authMethods(p.Key)
	if agentConn != nil {
		defer agentConn.Close()
	}
	if err != nil {
		conn.Close() // #nosec G104 — best-effort cleanup
		return nil, &AuthError{fmt.Errorf("probe %q: %w", p.Name, err)}
	}
	if len(methods) == 0 {
		conn.Close() // #nosec G104 — best-effort cleanup
		return nil, &AuthError{fmt.Errorf("probe %q: no authentication methods available — set key: <path> in the probe spec, or start ssh-agent and export SSH_AUTH_SOCK", p.Name)}
	}

	hostKeyCallback := ssh.HostKeyCallback(func(hostname string, _ net.Addr, _ ssh.PublicKey) error {
		return fmt.Errorf("probe %q: host key verification failed for %s — verify the key matches %s, or bypass with --skip-host-key-verify (CLI) / skip_host_key_verify: true (probe spec)", p.Name, hostname, p.Host)
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
		conn.Close() // #nosec G104 — best-effort cleanup
		return nil, classifyHandshakeError(p, err)
	}
	return ssh.NewClient(sshConn, chans, reqs), nil
}

// classifyHandshakeError maps an SSH handshake failure to a typed, actionable
// error. The markers are our own host-key callback message and the stable
// "unable to authenticate" text produced by x/crypto/ssh.
func classifyHandshakeError(p Probe, err error) error {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "host key verification failed"):
		return &HostKeyError{fmt.Errorf("probe %q: SSH host key verification failed for %s — the host key is not trusted; verify it matches %s, or bypass with --skip-host-key-verify (CLI) / skip_host_key_verify: true (probe spec)", p.Name, p.Host, p.Host)}
	case strings.Contains(msg, "unable to authenticate"):
		return &AuthError{fmt.Errorf("probe %q: SSH authentication failed for user %q at %s:22 — check the key: path in the probe spec and that the ssh-agent (SSH_AUTH_SOCK) holds the correct key", p.Name, p.User, p.Host)}
	default:
		return unreachableError(p, err)
	}
}

// unreachableError reports a transport-level failure (dial or handshake)
// with the probe identity and VLAN context needed to fix it.
func unreachableError(p Probe, err error) error {
	return &TransportError{fmt.Errorf("probe %q unreachable at %s:22 — is the host on VLAN %s and SSH running? (%w)", p.Name, p.Host, p.VLAN, err)}
}

// FromSpec converts an intent-spec probe declaration into the runtime probe
// used for SSH execution and diagnostics.
func FromSpec(p intent.Probe) Probe {
	return Probe{
		Name:              p.Name,
		Host:              p.Host,
		User:              p.User,
		Port:              p.Port,
		Key:               p.Key,
		VLAN:              p.VLAN,
		SkipHostKeyVerify: p.SkipHostKeyVerify,
	}
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

// Diagnose verifies that the probe is reachable and that SSH authentication
// succeeds, without executing any remote command. It is read-only. Failures
// are typed (HostKeyError, AuthError, TransportError) with actionable
// guidance. The probe's own SkipHostKeyVerify setting is honored, matching
// how audits run.
func Diagnose(ctx context.Context, p Probe) error {
	client, err := dialAndAuth(ctx, p, p.SkipHostKeyVerify)
	if err != nil {
		return err
	}
	client.Close() // #nosec G104 — best-effort cleanup
	return nil
}

// DiagnosticCheck performs a read-only reachability + SSH auth handshake and
// returns a doctor-style CheckResult with actionable guidance on failure.
func DiagnosticCheck(ctx context.Context, p Probe) *models.CheckResult {
	c := models.NewCheckResult("doctor", "probe_reachable", "local", p.Name)
	c.Expected["host"] = p.Host
	port := p.Port
	if port == 0 {
		port = 22
	}
	c.Expected["port"] = port
	c.Observed["user"] = p.User

	err := Diagnose(ctx, p)
	var hostKeyErr *HostKeyError
	var authErr *AuthError
	var transErr *TransportError
	switch {
	case err == nil:
		c.Status = models.StatusPass
		c.Summary = fmt.Sprintf("probe %q reachable at %s and SSH auth OK for user %q", p.Name, p.addr(), p.User)
		c.Observed["reachable"] = true
		c.Observed["auth_ok"] = true
	case errors.As(err, &hostKeyErr):
		c.Status = models.StatusFail
		c.Summary = fmt.Sprintf("probe %q reachable at %s but SSH host key is not trusted", p.Name, p.addr())
		c.Observed["reachable"] = true
		c.Observed["auth_ok"] = false
		c.Violations = append(c.Violations, err.Error())
	case errors.As(err, &authErr):
		c.Status = models.StatusFail
		c.Summary = fmt.Sprintf("probe %q reachable at %s but SSH authentication failed", p.Name, p.addr())
		c.Observed["reachable"] = true
		c.Observed["auth_ok"] = false
		c.Violations = append(c.Violations, err.Error())
	case errors.As(err, &transErr):
		c.Status = models.StatusFail
		c.Summary = fmt.Sprintf("probe %q unreachable at %s", p.Name, p.addr())
		c.Observed["reachable"] = false
		c.Observed["auth_ok"] = false
		c.Violations = append(c.Violations, err.Error())
	default:
		c.Status = models.StatusFail
		c.Summary = fmt.Sprintf("probe %q check failed: %v", p.Name, err)
	}
	c.Finish()
	return c
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
