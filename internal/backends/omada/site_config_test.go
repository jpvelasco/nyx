package omada

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestGetSiteConfig(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method %s", r.Method)
		}
		switch r.URL.Path {
		case "/openapi/v1/abc123/sites/s1/lan-networks":
			writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"vlan":10,"id":"n1","extension":{"z":9007199254740993,"a":1}}]}`)
		case "/openapi/v1/abc123/sites/s1/acls/osw-acls":
			writeEnvelope(w, 0, "", `[{"id":"r1","index":3}]`)
		case "/openapi/v1/abc123/sites/s1/wlan-groups":
			writeEnvelope(w, 0, "", `[{"id":"g1","name":"example"}]`)
		case "/openapi/v1/abc123/sites/s1/ssids":
			writeEnvelope(w, 0, "", `[{"id":"s1","wlanGroupId":"g1"}]`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	state, err := c.GetSiteConfig(context.Background(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"network", "switch-acl", "wlan-group", "ssid"} {
		if len(state.Resources[kind]) != 1 {
			t.Errorf("%s = %v, want one record", kind, state.Resources[kind])
		}
	}
	for _, resource := range state.Resources["network"] {
		if got := string(resource); got != `{"extension":{"a":1,"z":9007199254740993},"id":"n1","vlan":10}` {
			t.Errorf("unexpected canonical raw network %s", got)
		}
	}
}

func TestGetSiteConfigRejectsInvalidInventory(t *testing.T) {
	for _, tc := range []struct {
		name, result, want string
		code               int
	}{
		{"unavailable", `null`, "reading network configuration", -1005},
		{"missing id", `[{"name":"example"}]`, "resource is missing its id", 0},
		{"duplicate id", `[{"id":"n1"},{"id":"n1"}]`, "duplicate resource id", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/openapi/v1/abc123/sites/s1/lan-networks" {
					t.Errorf("unexpected path %s", r.URL.Path)
				}
				writeEnvelope(w, tc.code, "", tc.result)
			}))
			state, err := c.GetSiteConfig(context.Background(), "s1")
			if state.Resources != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("state = %v, error = %v", state, err)
			}
		})
	}
}

func TestSiteConfigRowRejectsInvalidJSON(t *testing.T) {
	var row siteConfigRow
	if err := json.Unmarshal([]byte(`[]`), &row); err == nil {
		t.Fatal("accepted a non-object config row")
	}
}
