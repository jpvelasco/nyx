package opnsense

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestSelectedPeerPublicTransport(t *testing.T) {
	const id = "00000000-0000-4000-8000-a00000000001"
	const server = "00000000-0000-4000-8000-a00000000002"
	reply := ""
	path := ""
	method := http.MethodPost
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method || r.URL.Path != "/api"+path {
			t.Error("wrong method or endpoint")
		}
		_, _ = w.Write([]byte(reply))
	})
	ctx := t.Context()
	d := SelectedPeer{Name: "trusted", Enabled: true, PublicKey: "public", Networks: []string{"10.0.10.0/24"}, Servers: []string{server}}
	for _, uuid := range []string{"", id} {
		path = "/wireguard/client/add_client"
		if uuid != "" {
			path = "/wireguard/client/set_client/" + id
		}
		for _, tc := range []struct {
			response string
			bad      bool
		}{{`{"result":"saved","uuid":"` + id + `"}`, false}, {`{"result":"failed"}`, true}, {`broken`, true}} {
			reply = tc.response
			got, err := c.SaveSelectedPeer(ctx, uuid, d)
			if (err != nil) != tc.bad || !tc.bad && got != id {
				t.Fatal(got, err)
			}
		}
	}
	path = "/wireguard/client/add_client"
	reply = `{"result":"saved"}`
	if _, err := c.SaveSelectedPeer(ctx, "", d); err == nil {
		t.Fatal("accepted missing created UUID")
	}
	if _, err := c.SaveSelectedPeer(ctx, "invalid", d); err == nil {
		t.Fatal("invalid peer selector")
	}
	method = http.MethodGet
	path = "/wireguard/client/get_client/" + id
	for _, tc := range []struct {
		body string
		bad  bool
	}{{`{"client":{"name":"trusted","pubkey":"public","enabled":"1","servers":"` + server + `","tunneladdress":"10.0.10.0/24","psk":"fixture-secret"}}`, false}, {`{"client":{"name":"trusted","pubkey":"public","enabled":"1","servers":"invalid","tunneladdress":"10.0.10.0/24"}}`, true}, {`{"client":{"name":"trusted","pubkey":"public","enabled":"1","servers":"","tunneladdress":""}}`, true}, {`{}`, true}, {`broken`, true}} {
		reply = tc.body
		r, err := c.SelectedPeer(ctx, id)
		if (err != nil) != tc.bad {
			t.Fatal(r, err)
		}
		b, _ := json.Marshal(r)
		if strings.Contains(string(b), "fixture-secret") {
			t.Fatal("secret surfaced")
		}
	}
	if _, err := c.SelectedPeer(ctx, "invalid"); err == nil {
		t.Fatal("invalid selector")
	}
	method = http.MethodPost
	for _, tc := range []struct {
		remove        bool
		path, success string
	}{{false, "toggle_client/" + id + "/0", "Disabled"}, {true, "del_client/" + id, "deleted"}} {
		path = "/wireguard/client/" + tc.path
		reply = `{"result":"` + tc.success + `"}`
		if err := c.RevokeWireGuardPeer(ctx, id, tc.remove); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.RevokeWireGuardPeer(ctx, "invalid", true); err == nil {
		t.Fatal("invalid selector")
	}
	path = "/wireguard/service/reconfigure"
	for _, s := range []string{`{"result":"ok"}`, `{"result":"failed"}`, `invalid`} {
		reply = s
		if err := c.ReloadWireGuard(ctx); (err == nil) != (strings.Contains(s, `"ok"`)) {
			t.Fatal(err)
		}
	}
}
