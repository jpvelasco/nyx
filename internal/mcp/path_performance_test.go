package mcp

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/service"
)

func TestPerformanceToolArgumentsAndUnavailableHop(t *testing.T) {
	t.Setenv("NYX_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials.json"))
	const path = `[{"connection":"absent/private-profile","kind":"gateway","name":"gateway"}]`
	s := newTestServer()
	for _, tc := range []struct {
		args map[string]any
		fail bool
	}{
		{map[string]any{"path": path, "connections": 42}, true},
		{map[string]any{"path": "[]"}, true},
		{map[string]any{"path": path, "interval": "1s"}, false},
	} {
		text, failed := s.DispatchToolForTest(t.Context(), service.PerformanceTool, tc.args)
		if failed != tc.fail {
			t.Fatal(text)
		}
		if !failed && (!strings.Contains(text, "insufficient_evidence") || !strings.Contains(text, "unsupported") || strings.Contains(text, "private-profile")) {
			t.Fatalf("unexpected unavailable hop response: %s", text)
		}
	}
}
