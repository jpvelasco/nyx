package mcp

import (
	"github.com/jpvelasco/nyx/internal/service"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientLocationArgumentBoundary(t *testing.T) {
	t.Setenv("NYX_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials.json"))
	s := newTestServer()
	for _, tc := range []struct {
		args map[string]any
		fail bool
	}{{map[string]any{"connections": 32}, true}, {map[string]any{"mac": "bad"}, true}, {map[string]any{"mac": "02:aa:bb:cc:dd:04", "connections": []any{"omada/missing"}}, false}} {
		text, fail := s.DispatchToolForTest(t.Context(), service.ClientLocationTool, tc.args)
		if fail != tc.fail || (!fail && !strings.Contains(text, "unconfirmed")) {
			t.Fatal(tc, text)
		}
	}
}
