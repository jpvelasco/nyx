package mcp

import (
	"slices"
	"strings"
	"testing"
)

func TestMaintenanceToolsUseConfiguredTarget(t *testing.T) {
	hermeticCreds(t)
	s := NewServerWithLogger(nil)
	for _, name := range []string{"omada_pending_devices", "omada_adoption_status", "omada_staged_firmware"} {
		if !slices.Contains(ToolNames(), name) {
			t.Fatal("missing", name)
		}
		for _, key := range []string{"host", "password", "url", "file", "skip_tls_verify"} {
			out, failed := s.dispatchTool(t.Context(), name, map[string]interface{}{key: "private.example"})
			if !failed || !strings.Contains(out, "unsupported maintenance argument") || strings.Contains(out, "private.example") {
				t.Errorf("%s accepted override %s", name, key)
			}
		}
		if _, failed := s.dispatchTool(t.Context(), name, nil); !failed {
			t.Fatal("accepted unconfigured target")
		}
	}
	for _, tc := range []struct {
		name, key string
		value     any
	}{{"omada_pending_devices", "page", 0.5}, {"omada_staged_firmware", "confirm_reboot", "true"}, {"omada_adoption_status", "mac", true}} {
		if _, failed := s.dispatchTool(t.Context(), tc.name, map[string]any{tc.key: tc.value}); !failed {
			t.Errorf("accepted malformed %s", tc.key)
		}
	}
}
