package opnsense

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestGetFirewallLog(t *testing.T) {
	const cursor = "0123456789abcdef0123456789abcdef"
	const next = "fedcba9876543210fedcba9876543210"
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/diagnostics/firewall/log" || r.URL.RawQuery != "limit=5000" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
		}
		_, _ = w.Write([]byte(`[
   {"__digest__":"` + cursor + `"},
   {"src":"2001:db8::1/1234","dst":"192.0.2.1/443","srcport":"1234","dstport":"443","action":"pass","dir":"in","interface":"lan","label":"sample\u001b\u0085\u202e","__timestamp__":"2026-11-18T12:00:00","__digest__":"00000000000000000000000000000000"},
   {"src":"192.0.2.2","dst":"192.0.2.1","action":"block","dir":"out","interface":"wan","__timestamp__":"2026-11-18T11:59:00Z","__digest__":"` + next + `"}
  ]`))
	})
	query := FirewallLogQuery{Limit: 2, Before: strings.ToUpper(cursor), Source: "2001:db8::/32", Destination: "192.0.2.1", Action: "PASS", Direction: "in", Interface: "lan", Since: "2026-11-18T12:00:00Z"}
	page, err := client.GetFirewallLog(t.Context(), query)
	if err != nil || page.NextBefore != next || len(page.Rows) != 1 || page.Rows[0].Label != "sample" || page.Rows[0].DestinationPort != "443" {
		t.Fatalf("page = %+v, err = %v", page, err)
	}
	query.Since = "2026-11-18T12:00:01Z"
	page, err = client.GetFirewallLog(t.Context(), query)
	if err != nil || page.NextBefore != next || page.Rows == nil || len(page.Rows) != 0 {
		t.Fatalf("filtered page = %+v, err = %v", page, err)
	}
}

func TestGetFirewallLogErrors(t *testing.T) {
	for _, tt := range []struct {
		name    string
		status  int
		body    string
		query   FirewallLogQuery
		message string
	}{
		{name: "permission", status: 403, message: "Diagnostics: Logs: Firewall: Live View"},
		{name: "malformed", status: 200, body: `{"rows":[]}`, message: "expected an array"},
		{name: "cursor", query: FirewallLogQuery{Before: "bad"}, message: "hexadecimal digest"},
		{name: "limit", query: FirewallLogQuery{Limit: 1001}, message: "limit must be"},
		{name: "since", query: FirewallLogQuery{Since: "yesterday"}, message: "RFC3339 timestamp"},
		{name: "missing cursor", status: 200, body: `[]`, query: FirewallLogQuery{Before: "0123456789abcdef0123456789abcdef"}, message: "outside the newest 5000"},
		{name: "missing digest", status: 200, body: `[{}]`, message: "invalid final digest"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				if tt.status == 0 {
					t.Error("invalid request reached controller")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.status)
				if tt.body != "" {
					if err := json.NewEncoder(w).Encode(json.RawMessage(tt.body)); err != nil {
						t.Errorf("encode fixture: %v", err)
					}
				}
			})
			_, err := c.GetFirewallLog(t.Context(), tt.query)
			if err == nil || !strings.Contains(err.Error(), tt.message) {
				t.Fatalf("got %v, want %q", err, tt.message)
			}
		})
	}
}

func TestGetFirewallLogStats(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/diagnostics/firewall/stats" || r.URL.RawQuery != "group_by=dstport&limit=20" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
		}
		_, _ = w.Write([]byte(`[{"label":443,"value":3},{"label":"other\u001b","value":1}]`))
	})
	rows, err := client.GetFirewallLogStats(t.Context(), 20, "dstport")
	if err != nil || len(rows) != 2 || rows[0] != (FirewallLogStat{Label: "443", Value: 3}) || rows[1] != (FirewallLogStat{Label: "other", Value: 1}) {
		t.Fatalf("rows = %+v, error = %v", rows, err)
	}
}

func TestGetFirewallLogStatsForbidden(t *testing.T) {
	client, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "group_by=interface&limit=5000" {
			t.Errorf("unexpected query %s", r.URL.RawQuery)
		}
		w.WriteHeader(http.StatusForbidden)
	})
	_, err := client.GetFirewallLogStats(t.Context(), 0, "")
	if err == nil || !strings.Contains(err.Error(), "Diagnostics: Logs: Firewall: Summary View") {
		t.Fatalf("error = %v", err)
	}
}

func TestParseFirewallLogTimestamp(t *testing.T) {
	now := time.Date(2026, time.January, 2, 0, 0, 0, 0, time.UTC)
	zone := time.FixedZone("firewall", 3600)
	for _, tt := range []struct{ input, want string }{
		{"Dec 31 23:59:59", "2025-12-31T23:59:59+01:00"},
		{"Jan 1 03:00:00", "2026-01-01T03:00:00+01:00"},
		{"2026-01-01T03:00:00.123", "2026-01-01T03:00:00+01:00"},
		{"2026-01-01T03:00:00-05:00", "2026-01-01T03:00:00-05:00"},
	} {
		timestamp, err := parseFirewallLogTimestamp(tt.input, zone, now)
		if err != nil || timestamp.Format(time.RFC3339) != tt.want {
			t.Errorf("%q: timestamp = %v, error = %v", tt.input, timestamp, err)
		}
	}
}
