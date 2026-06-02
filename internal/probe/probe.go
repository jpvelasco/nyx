// Package probe implements remote execution of certain assertions over SSH from declared probe hosts (for multi-VLAN vantage points).
package probe

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Probe represents a remote node that can execute commands via SSH.
type Probe struct {
	Name string // probe name
	Host string // IP or hostname
	User string // SSH username
	Key  string // path to private key; empty = ssh-agent only
	VLAN string // informational label
}

// Run executes a command on the probe and returns combined stdout+stderr output.
// Each argument is shell-quoted before joining so args with spaces or special
// characters are preserved across the SSH shell boundary.
// On dial failure, returns a descriptive error mentioning the probe name, host, and VLAN.
func Run(ctx context.Context, p Probe, cmd []string) (string, error) {
	conn, err := dialWithContext(ctx, p)
	if err != nil {
		return "", fmt.Errorf("probe %q unreachable at %s:22 — is the host on VLAN %s and SSH running?", p.Name, p.Host, p.VLAN)
	}
	defer conn.Close()

	// Build auth methods; agentConn (if any) must stay open until the session ends.
	methods, agentConn := authMethods(p.Key)
	if agentConn != nil {
		defer agentConn.Close()
	}
	if len(methods) == 0 {
		return "", fmt.Errorf("probe %q: no authentication methods available", p.Name)
	}

	cfg := &ssh.ClientConfig{
		User:            p.User,
		Auth:            methods,
		// nosemgrep
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // homelab probe, not a security boundary
		Timeout:         10 * time.Second,
	}

	sshConn, chans, reqs, err := ssh.NewClientConn(conn, p.Host+":22", cfg)
	if err != nil {
		return "", fmt.Errorf("probe %q unreachable at %s:22 — is the host on VLAN %s and SSH running?", p.Name, p.Host, p.VLAN)
	}
	defer sshConn.Close()

	client := ssh.NewClient(sshConn, chans, reqs)
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("probe %q: failed to create SSH session: %w", p.Name, err)
	}
	defer session.Close()

	// Shell-quote each argument so args with spaces/special chars survive the
	// remote shell boundary without being interpreted.
	quoted := make([]string, len(cmd))
	for i, arg := range cmd {
		quoted[i] = shellQuote(arg)
	}
	output, err := session.CombinedOutput(strings.Join(quoted, " "))
	return string(output), err
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
	conn.Close()
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

	return net.DialTimeout("tcp", p.Host+":22", timeout)
}

// authMethods builds the SSH auth method chain: private key (if provided) then ssh-agent.
// Returns the agent connection if one was opened — the caller must close it after the
// SSH session ends (closing it too early would break agent-based auth mid-handshake).
func authMethods(keyPath string) ([]ssh.AuthMethod, net.Conn) {
	var methods []ssh.AuthMethod

	if keyPath != "" {
		if strings.HasPrefix(keyPath, "~/") {
			home, err := os.UserHomeDir()
			if err == nil {
				keyPath = filepath.Join(home, keyPath[2:])
			}
		}
		keyBytes, err := os.ReadFile(keyPath)
		if err == nil {
			signer, err := ssh.ParsePrivateKey(keyBytes)
			if err == nil {
				methods = append(methods, ssh.PublicKeys(signer))
			}
		}
	}

	agentConn := connectAgent()
	if agentConn != nil {
		agentClient := agent.NewClient(agentConn)
		methods = append(methods, ssh.PublicKeysCallback(agentClient.Signers))
	}

	return methods, agentConn
}

// connectAgent attempts to connect to the SSH agent via SSH_AUTH_SOCK.
// Returns nil if unavailable.
func connectAgent() net.Conn {
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return nil
	}

	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil
	}

	return conn
}
