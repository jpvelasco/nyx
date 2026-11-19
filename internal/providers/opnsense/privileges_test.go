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

func TestCheckPrivilegesStopsOnUnauthorized(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/firewall/alias/get" {
			t.Errorf("unexpected request after authentication failure: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer server.Close()

	rows, err := NewClient(server.URL, "fixture-key", "fixture-secret", true, "").CheckPrivileges(t.Context())
	if err == nil || len(rows) != 0 {
		t.Fatalf("rows = %q, error = %v. Want an authentication failure before reporting rows", rows, err)
	}
}

func TestCheckPrivilegesIdentifiesDeniedPages(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	rows, err := NewClient(server.URL, "fixture-key", "fixture-secret", true, "").CheckPrivileges(t.Context())
	if err == nil {
		t.Fatal("expected denied privileges")
	}
	for _, privilege := range []string{
		"Diagnostics: Logs: Firewall: Live View",
		"System: Status",
		"Services: DHCP: Kea(v4)",
		"Services: DHCP: Kea(v6)",
		"Services: Dnsmasq DNS/DHCP: Settings",
		"Diagnostics: PF Table IP addresses",
	} {
		if !strings.Contains(strings.Join(rows, "\n"), "blocked by privilege ("+privilege+")") {
			t.Errorf("missing %q in privilege report: %v", privilege, rows)
		}
	}
}
