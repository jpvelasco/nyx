//go:build !windows

package probe

import (
	"net"
)

// dialAgent connects to the SSH agent socket. Unix systems use a unix socket.
// The socket path comes from SSH_AUTH_SOCK (env), not user-controlled input.
func dialAgent(socket string) (net.Conn, error) {
	return net.Dial("unix", socket) // #nosec G704 — SSH agent socket from env, not user-controlled
}
