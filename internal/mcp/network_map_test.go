package mcp

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/service"
)

func TestNetworkMapDispatchPrivacy(t *testing.T) {
	t.Setenv("NYX_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials.json"))
	s := newTestServer()
	if !slices.Contains(ToolNames(), service.NetworkMapTool) {
		t.Fatal("network_map absent from tools/list")
	}
	for _, tc := range []struct {
		name, allow string
		args        map[string]any
		failure     bool
		want        string
	}{
		{"public", "", map[string]any{"connections": []any{"omada/private-profile"}}, false, "missing_credentials"},
		{"detail gate", "", map[string]any{"include_detail": true}, true, "NYX_MCP_ALLOW_TOPOLOGY_DETAILS"},
		{"private", "true", map[string]any{"include_detail": true, "connections": []any{"omada/private-profile"}}, false, "private-profile"},
		{"malformed", "", map[string]any{"connections": []any{42}}, true, "selector"},
		{"unregistered", "", map[string]any{"connections": []any{"absent/home"}}, true, "unregistered"},
		{"empty", "", map[string]any{"connections": []any{}}, true, "nonempty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("NYX_MCP_ALLOW_TOPOLOGY_DETAILS", tc.allow)
			text, failed := s.DispatchToolForTest(t.Context(), service.NetworkMapTool, tc.args)
			if failed != tc.failure || !strings.Contains(text, tc.want) {
				t.Fatalf("failed=%t text=%s", failed, text)
			}
			if !failed && (!strings.Contains(text, `"untrusted_data": true`) || (tc.name == "public" && strings.Contains(text, "private-profile"))) {
				t.Fatalf("unsafe output %s", text)
			}
		})
	}
}
