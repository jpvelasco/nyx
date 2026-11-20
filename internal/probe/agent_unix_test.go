//go:build !windows

package probe

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

// listenAgent opens a fake SSH agent socket and returns its SSH_AUTH_SOCK
// value. The directory comes from os.MkdirTemp rather than t.TempDir: macOS
// caps unix socket paths at 104 bytes, and t.TempDir embeds the test name.
func listenAgent(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "nyx")
	if err != nil {
		t.Fatalf("creating socket dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sockPath := filepath.Join(dir, "agent.sock")
	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("creating unix socket: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return sockPath
}
