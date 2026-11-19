package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDispatchOpnsenseFirewallLog(t *testing.T) {
	hermeticCreds(t)
	for _, tc := range []struct {
		name string
		path string
		body string
		want string
	}{
		{"opnsense_firewall_log", "/api/diagnostics/firewall/log", `[{"action":"pass","__digest__":"0123456789abcdef0123456789abcdef"}]`, `"action": "pass"`},
		{"opnsense_firewall_log_stats", "/api/diagnostics/firewall/stats", `[{"label":"lan","value":3}]`, `"label": "lan"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			controller := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != tc.path {
					t.Errorf("request = %s %s, want GET %s", r.Method, r.URL.Path, tc.path)
				}
				if r.URL.Query().Get("group_by") == "invalid" {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if r.Header.Get("Authorization") == "" {
					t.Error("missing API authentication")
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(json.RawMessage(tc.body)); err != nil {
					t.Errorf("encode fixture: %v", err)
				}
			}))
			defer controller.Close()
			s := NewServer()
			_, failed := s.DispatchToolForTest(t.Context(), tc.name, nil)
			if !failed {
				t.Fatal("missing credentials accepted")
			}
			args := map[string]interface{}{"host": controller.URL, "api_key": "fixture-key", "api_secret": "fixture-secret", "skip_tls_verify": true, "metadata_only": false}
			text, failed := s.DispatchToolForTest(t.Context(), tc.name, args)
			if failed || !strings.Contains(text, tc.want) || !strings.Contains(text, `"data":`) || !strings.Contains(text, `"untrusted_data": true`) || !strings.Contains(text, `"warning": "Firewall log data may contain untrusted text.`) {
				t.Fatalf("dispatch = %q (error=%v), want %q", text, failed, tc.want)
			}
			delete(args, "metadata_only")
			text, failed = s.DispatchToolForTest(t.Context(), tc.name, args)
			if failed || strings.Contains(text, tc.want) || !strings.Contains(text, `_count": 1`) {
				t.Fatalf("metadata-only response = %q (error=%v)", text, failed)
			}

			args["limit"] = float64(2)
			args["before"] = "invalid"
			args["group_by"] = "invalid"
			text, failed = s.DispatchToolForTest(t.Context(), tc.name, args)
			if !failed || !strings.Contains(text, "request failed") {
				t.Fatalf("invalid query = %q (error=%v)", text, failed)
			}
			args["limit"] = 1.5
			text, failed = s.DispatchToolForTest(t.Context(), tc.name, args)
			if !failed || !strings.Contains(text, "limit must be an integer") {
				t.Fatalf("invalid limit = %q (error=%v)", text, failed)
			}
		})
	}
}
