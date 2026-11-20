//go:build windows

package probe

import (
	"fmt"
	"os"
	"testing"

	"github.com/Microsoft/go-winio"
)

// listenAgent opens a fake SSH agent named pipe, the transport dialAgent
// uses on Windows, and returns its SSH_AUTH_SOCK value.
func listenAgent(t *testing.T) string {
	t.Helper()
	pipe := fmt.Sprintf(`\\.\pipe\nyx-agent-test-%d`, os.Getpid())
	ln, err := winio.ListenPipe(pipe, nil)
	if err != nil {
		t.Fatalf("creating agent pipe: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return pipe
}
