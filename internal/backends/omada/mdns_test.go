package omada

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestFetchMDNSInventoryPages(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/openapi/v1/abc123/sites/s1/setting/service/mdns" || r.URL.Query().Get("pageSize") != "200" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch r.URL.Query().Get("page") {
		case "1":
			writeEnvelope(w, 0, "", `{"totalRows":2,"currentPage":1,"data":[{
				"id":"m\t1","name":"me\ndia\u001b","status":true,"profileIds":["p\u202e1"],"type":1,
				"osg":{"serviceNetworks":["n\r1"],"clientNetworks":["n\u007f2","n3"]}}]}`)
		case "2":
			writeEnvelope(w, 0, "", `{"totalRows":2,"currentPage":2,"data":[{
				"id":"m2","name":"gaming","status":false,"profileIds":[],"type":0,
				"ap":{"serviceVlan":"3\u00000","clientVlan":"10-\t11,20"}}]}`)
		default:
			t.Errorf("unexpected page %s", r.URL.RawQuery)
			w.WriteHeader(http.StatusBadRequest)
		}
	}))
	inv := c.fetchMDNSInventory(context.Background(), "s1")
	if inv.Status != mdnsAvailable || len(inv.Rules) != 2 {
		t.Fatalf("mDNS inventory = %+v, want two available rules", inv)
	}
	if inv.Rules[0].Name != "media" || inv.Rules[0].ID != "m1" || inv.Rules[0].ProfileIDs[0] != "p1" {
		t.Errorf("structured fields retain controller control characters: %+v", inv.Rules[0])
	}
	out := RenderInventory(&InventorySnapshot{MDNS: inv}, "HQ")
	for _, want := range []string{
		"2 rules",
		`"media" ("m1") enabled=true  service network IDs: "n1"  client network IDs: "n2, n3"  Bonjour profile IDs: "p1"`,
		`"gaming" ("m2") enabled=false  service VLAN: "30"  client VLANs: "10-11,20"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("inventory missing %q:\n%s", want, out)
		}
	}
}

func TestFetchMDNSInventoryStatus(t *testing.T) {
	tests := []struct {
		name   string
		code   int
		body   string
		status string
		line   string
	}{
		{name: "missing rule setting", body: `{"totalRows":1,"data":[{"type":0}]}`, status: mdnsUnknown, line: "mdns: unknown"},
		{name: "empty", body: `{"totalRows":0,"data":[]}`, status: mdnsAvailable, line: "0 rules"},
		{name: "unsupported", code: -1600, body: `null`, status: mdnsUnavailable, line: "mdns: api-unavailable (UI-only; configuration unknown)"},
		{name: "forbidden", code: -1005, body: `null`, status: mdnsUnknown, line: "mdns: unknown (API read failed)"},
		{name: "invalid payload", body: `{"data":[{"status":"true"}]}`, status: mdnsUnknown, line: "mdns: unknown (API read failed)"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				writeEnvelope(w, tc.code, "", tc.body)
			}))
			inv := c.fetchMDNSInventory(context.Background(), "s1")
			if inv.Status != tc.status || len(inv.Rules) != 0 || (inv.Rules != nil) != (tc.status == mdnsAvailable) {
				t.Errorf("inventory = %+v, want %q with no observed rules", inv, tc.status)
			}
			if out := RenderInventory(&InventorySnapshot{MDNS: inv}, "HQ"); !strings.Contains(out, tc.line) {
				t.Errorf("inventory missing %q:\n%s", tc.line, out)
			}
		})
	}
}
