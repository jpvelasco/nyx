package cli

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
)

func TestOpnsenseBlocklist(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		path    string
		bodyKey string
		value   string
		output  string
		reply   string
		wantErr string
	}{
		{name: "tables", args: []string{"list-tables"}, path: "aliases", output: "sshlockout", reply: `["sshlockout"]`},
		{name: "filtered rows", args: []string{"list", "sshlockout", "--search", "192.0.2"}, path: "list/sshlockout", bodyKey: "searchPhrase", value: "192.0.2", output: "192.0.2.9", reply: `{"rows":[{"ip":"192.0.2.9"}],"total":1}`},
		{name: "references", args: []string{"references", "2001:db8::1"}, path: "find_references", bodyKey: "ip", value: "2001:db8::1", output: "matches", reply: `{"status":"done","matches":[]}`},
		{name: "unblock preview", args: []string{"unblock", "sshlockout", "192.0.2.9"}, output: "dry_run"},
		{name: "flush preview", args: []string{"flush", "sshlockout"}, output: "dry_run"},
		{name: "confirmed unblock", args: []string{"unblock", "sshlockout", "192.0.2.0/24", "--confirm"}, path: "delete/sshlockout", bodyKey: "address", value: "192.0.2.0/24", output: "acknowledged", reply: `{"status":"done"}`},
		{name: "confirmed flush", args: []string{"flush", "sshlockout", "--confirm"}, path: "flush/sshlockout", output: "acknowledged", reply: `{"status":"done"}`},
		{name: "rejected flush", args: []string{"flush", "sshlockout", "--confirm"}, path: "flush/sshlockout", reply: `{"status":"failed"}`, wantErr: "did not acknowledge"},
		{name: "invalid table", args: []string{"flush", "../sshlockout", "--confirm"}, wantErr: "invalid pf table"},
		{name: "invalid address", args: []string{"unblock", "sshlockout", "ALL", "--confirm"}, wantErr: "requires an IP address"},
		{name: "invalid reference", args: []string{"references", "192.0.2.0/24"}, wantErr: "requires an IPv4 or IPv6 address"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			saveRestoreGlobals(t)
			var requests atomic.Int32
			ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				method := http.MethodPost
				if tc.path == "aliases" {
					method = http.MethodGet
				}
				if tc.path == "" || r.Method != method || r.URL.Path != "/api/firewall/alias_util/"+tc.path {
					t.Errorf("unexpected endpoint: %s %s", r.Method, r.URL.Path)
				}
				if tc.bodyKey != "" {
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body[tc.bodyKey] != tc.value {
						t.Errorf("body = %v, %v", body, err)
					}
				}
				testutil.WriteBody(w, tc.reply)
			}))
			t.Cleanup(ts.Close)
			cmd := buildOpnsenseBlocklistCmd()
			cmd.SetArgs(tc.args)
			cmd.SilenceErrors, cmd.SilenceUsage = true, true
			providerHost, providerSkipTLS = ts.URL, true
			var err error
			out := captureStdout(func() { err = cmd.Execute() })
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error = %v, want %q", err, tc.wantErr)
				}
			} else if err != nil || !strings.Contains(out, tc.output) {
				t.Errorf("output = %q, error = %v; want %q", out, err, tc.output)
			}
			wantRequests := int32(0)
			if tc.path != "" {
				wantRequests = 1
			}
			if got := requests.Load(); got != wantRequests {
				t.Errorf("requests = %d, want %d", got, wantRequests)
			}
		})
	}
}
