package opnsense

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
)

func TestGetDHCPLeases(t *testing.T) {
	const (
		dnsSettings = "/api/dnsmasq/settings/get"
		dnsLeases   = "/api/dnsmasq/leases/search"
		keaV4       = "/api/kea/leases4/search"
		keaV6       = "/api/kea/leases6/search"
		dnsEnabled  = `{"dnsmasq":{"enable":"1"}}`
		dnsDisabled = `{"dnsmasq":{"enable":"0"}}`
		noRows      = `{"total":0,"rows":[]}`
	)
	type response struct {
		path   string
		body   string
		status int
	}
	for _, tc := range []struct {
		name      string
		responses []response
		want      []DHCPLease
		wantErr   string
	}{
		{
			name:      "enabled dnsmasq with active leases",
			responses: []response{{path: dnsSettings, body: dnsEnabled}, {path: dnsLeases, body: `{"total":1,"rows":[{"hostname":"printer","address":"10.0.10.20","hwaddr":"aa:bb:cc:dd:ee:01"}]}`}},
			want:      []DHCPLease{{Hostname: "printer", IP: "10.0.10.20", MAC: "aa:bb:cc:dd:ee:01"}},
		},
		{
			name:      "enabled dnsmasq with legitimately zero leases",
			responses: []response{{path: dnsSettings, body: dnsEnabled}, {path: dnsLeases, body: noRows}},
		},
		{
			name: "Kea reads both families and skips inactive leases",
			responses: []response{
				{path: dnsSettings, body: dnsDisabled},
				{path: keaV4, body: `{"total":2,"rows":[{"hostname":"printer","address":"10.0.10.20","hwaddr":"aa:bb:cc:dd:ee:01","state":0},{"address":"10.0.10.21","state":1}]}`},
				{path: keaV6, body: `{"total":1,"rows":[{"hostname":"server","address":"2001:db8::10","state":0}]}`},
			},
			want: []DHCPLease{{Hostname: "printer", IP: "10.0.10.20", MAC: "aa:bb:cc:dd:ee:01"}, {Hostname: "server", IP: "2001:db8::10"}},
		},
		{
			name:      "legacy response still decodes",
			responses: []response{{path: dnsSettings, body: dnsEnabled}, {path: dnsLeases, body: `{"leases":[{"hostname":"printer","ip":"10.0.10.20","mac":"aa:bb:cc:dd:ee:01"}]}`}},
			want:      []DHCPLease{{Hostname: "printer", IP: "10.0.10.20", MAC: "aa:bb:cc:dd:ee:01"}},
		},
		{
			name:      "denied settings do not guess the backend",
			responses: []response{{path: dnsSettings, status: http.StatusForbidden}}, wantErr: "Services: Dnsmasq DNS/DHCP: Settings",
		},
		{
			name:      "denied dnsmasq lease search",
			responses: []response{{path: dnsSettings, body: dnsEnabled}, {path: dnsLeases, status: http.StatusForbidden}}, wantErr: "Services: Dnsmasq DNS/DHCP: Settings",
		},
		{
			name:      "denied Kea v4 search",
			responses: []response{{path: dnsSettings, body: dnsDisabled}, {path: keaV4, status: http.StatusForbidden}}, wantErr: "Services: DHCP: Kea(v4)",
		},
		{
			name:      "denied Kea v6 search",
			responses: []response{{path: dnsSettings, body: dnsDisabled}, {path: keaV4, body: noRows}, {path: keaV6, status: http.StatusForbidden}}, wantErr: "Services: DHCP: Kea(v6)",
		},
		{
			name:      "missing Kea endpoint",
			responses: []response{{path: dnsSettings, body: dnsDisabled}, {path: keaV4, body: noRows}, {path: keaV6, status: http.StatusNotFound}}, wantErr: "endpoint not present in this OPNsense version",
		},
		{
			name:      "malformed lease data",
			responses: []response{{path: dnsSettings, body: dnsEnabled}, {path: dnsLeases, body: `not json`}}, wantErr: "decoding DHCP leases response",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var paths []string
			c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				paths = append(paths, r.URL.Path)
				i := len(paths) - 1
				if i >= len(tc.responses) || r.URL.Path != tc.responses[i].path {
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
					return
				}
				if r.URL.Path == dnsSettings {
					if r.Method != http.MethodGet {
						t.Errorf("settings method = %s, want GET", r.Method)
					}
				} else {
					var req struct {
						RowCount int               `json:"rowCount"`
						Sort     map[string]string `json:"sort"`
					}
					if err := json.NewDecoder(r.Body).Decode(&req); r.Method != http.MethodPost || err != nil || req.RowCount != -1 || req.Sort["expire"] != "desc" {
						t.Errorf("search = %s %+v %v, want POST for all leases sorted by expiry", r.Method, req, err)
					}
				}
				resp := tc.responses[i]
				if resp.status != 0 {
					w.WriteHeader(resp.status)
					return
				}
				testutil.WriteBody(w, resp.body)
			}))
			got, err := c.GetDHCPLeases(context.Background())
			if len(paths) != len(tc.responses) {
				t.Errorf("requests = %v, want %d", paths, len(tc.responses))
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) || got != nil {
					t.Errorf("leases = %+v, error = %v, want error containing %q", got, err, tc.wantErr)
				}
				return
			}
			if err != nil || !slices.Equal(got, tc.want) {
				t.Errorf("leases = %+v, error = %v, want %+v", got, err, tc.want)
			}
		})
	}
}
