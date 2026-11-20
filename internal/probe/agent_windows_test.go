//go:build windows

package probe

import (
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/Microsoft/go-winio"
)

// listenAgent opens a fake SSH agent named pipe, the transport dialAgent
// uses on Windows, and returns its SSH_AUTH_SOCK value. Unlike a unix
// socket's listen backlog, a pipe client connects only once the server
// accepts, so the fake agent keeps accepting until the test ends.
func listenAgent(t *testing.T) string {
	t.Helper()
	pipe := fmt.Sprintf(`\\.\pipe\nyx-agent-test-%d`, os.Getpid())
	ln, err := winio.ListenPipe(pipe, nil)
	if err != nil {
		t.Fatalf("creating agent pipe: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(io.Discard, conn)
			}()
		}
	}()
	return pipe
}
