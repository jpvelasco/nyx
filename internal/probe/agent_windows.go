//go:build windows

package probe

import (
	"net"

	"github.com/Microsoft/go-winio"
)

// dialAgent connects to the SSH agent socket. Windows OpenSSH sets
// SSH_AUTH_SOCK to a named pipe (e.g. \\.\pipe\openssh-ssh-agent), which
// net.Dial("unix", ...) cannot open — winio.DialPipe handles the pipe path.
func dialAgent(socket string) (net.Conn, error) {
	return winio.DialPipe(socket, nil)
}
