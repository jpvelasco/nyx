package mcp

import (
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/jpvelasco/nyx/internal/snapshot"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDriftToolArgumentsAndReceipt(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("NYX_CREDENTIALS_FILE", filepath.Join(home, "creds.json"))
	for _, n := range []string{"x", "y"} {
		if err := snapshot.SaveNetworkMapCapture(n, snapshot.NetworkMapCapture{Version: 1, At: time.Now()}, false); err != nil {
			t.Fatal(err)
		}
	}
	s := newTestServer()
	for _, tc := range []struct {
		tool string
		args map[string]any
		fail bool
	}{{service.MapDriftTool, map[string]any{"before": "x", "after": "y"}, false}, {service.MapDriftTool, map[string]any{"before": "x", "after": "unknown"}, true}, {service.MapDriftTool, map[string]any{"connections": true}, true}, {service.MapCaptureTool, map[string]any{"connections": true}, true}, {service.MapCaptureTool, map[string]any{"name": "z", "connections": []any{"omada/missing"}}, false}, {service.MapCaptureTool, map[string]any{"name": "../invalid", "connections": []any{"omada/missing"}}, true}} {
		result, fail := s.DispatchToolForTest(t.Context(), tc.tool, tc.args)
		if fail != tc.fail || (!fail && !strings.Contains(result, "untrusted_data")) {
			t.Fatal(tc, result)
		}
	}
}
