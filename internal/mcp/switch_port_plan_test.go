package mcp

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/service"
)

func TestSwitchPortPlanRequiresPolicyAndConnection(t *testing.T) {
	t.Setenv("NYX_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials.json"))
	s := newTestServer()
	const policy = `{"management_vlan":11,"ports":[{"port":8,"role":"access","native":"gaming"}]}`
	for _, tc := range []struct {
		args   map[string]any
		reason string
	}{
		{map[string]any{"policy": "{}"}, "management_vlan"},
		{map[string]any{"policy": policy, "connections": 42}, "connections"},
		{map[string]any{"policy": policy, "connection": "opnsense/home"}, "Omada"},
	} {
		text, fail := s.DispatchToolForTest(t.Context(), service.SwitchPortsTool, tc.args)
		if !fail || !strings.Contains(text, tc.reason) {
			t.Fatalf("unexpected result: %s", text)
		}
	}
}
