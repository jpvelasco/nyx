package opnsense

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCheckPrivileges(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/firewall/filter/search_rule":
			if r.Method != http.MethodPost {
				t.Errorf("method = %s, want POST", r.Method)
			}
			w.WriteHeader(http.StatusForbidden)
		case "/api/kea/leases6/search":
			w.WriteHeader(http.StatusNotFound)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()
	rows, err := NewClient(server.URL, "fixture-key", "fixture-secret", true, "").CheckPrivileges(t.Context())
	if err == nil || !strings.Contains(err.Error(), "Firewall: Rules [new]") {
		t.Fatalf("error = %v, want missing rule privilege", err)
	}
	if len(rows) != 8 || !strings.Contains(strings.Join(rows, "\n"), "/kea/leases6/search\tmissing in this version") {
		t.Errorf("rows = %q, want complete privilege report", rows)
	}
}
