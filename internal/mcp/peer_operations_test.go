package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
)

func TestPeerPreviewAndRevocation(t *testing.T) {
	hermeticCreds(t)
	const id = "00000000-0000-4000-8000-a00000000001"
	const other = "00000000-0000-4000-8000-a00000000002"
	enabled, exists, deny, reloadFail := true, true, false, false
	disables, deletes, reloads := 0, 0, 0
	firewall := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if deny {
			w.WriteHeader(http.StatusForbidden)
			testutil.WriteBody(w, "restricted device error")
			return
		}
		switch r.URL.Path {
		case "/api/wireguard/client/search_client":
			rows := []map[string]string{{"uuid": other, "name": "management", "enabled": "1", "tunneladdress": "10.0.11.0/24"}}
			if exists {
				state := "0"
				if enabled {
					state = "1"
				}
				rows = append(rows, map[string]string{"uuid": id, "name": "trusted", "enabled": state, "tunneladdress": "10.0.10.0/24", "privkey": "fixture-private", "psk": "fixture-preshared"})
			}
			if err := json.NewEncoder(w).Encode(map[string]any{"rows": rows, "total": len(rows)}); err != nil {
				t.Error(err)
			}
		case "/api/wireguard/client/toggle_client/" + id + "/0":
			disables++
			enabled = false
			testutil.WriteBody(w, `{"result":"Disabled"}`)
		case "/api/wireguard/client/del_client/" + id:
			deletes++
			exists = false
			testutil.WriteBody(w, `{"result":"deleted"}`)
		case "/api/wireguard/service/reconfigure":
			reloads++
			if reloadFail {
				testutil.WriteBody(w, `{"result":"failed"}`)
			} else {
				testutil.WriteBody(w, `{"result":"ok"}`)
			}
		case "/api/wireguard/service/status":
			testutil.WriteBody(w, `{"status":"running"}`)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer firewall.Close()
	args := map[string]interface{}{"host": strings.TrimPrefix(firewall.URL, "https://"), "api_key": "test", "api_secret": "fixture-secret", "skip_tls_verify": true}
	s := NewServerWithLogger(nil)
	call := func(name string, wantError bool, needle string) {
		t.Helper()
		got, failed := s.dispatchTool(t.Context(), name, args)
		if failed != wantError || !strings.Contains(got, needle) || strings.Contains(got, "fixture-private") || strings.Contains(got, "fixture-preshared") {
			t.Fatal(got)
		}
	}
	const plan = "opnsense_plan_wireguard_peer"
	const revoke = "opnsense_revoke_wireguard_peer"
	args["action"] = "create"
	args["name"] = "iot"
	args["allowed_networks"] = "10.0.11.0/24"
	call(plan, false, "overlap")
	args["allowed_networks"] = "invalid"
	call(plan, true, "prefixes")
	delete(args, "name")
	args["uuid"] = id
	args["action"] = "update"
	args["allowed_networks"] = "10.0.10.0/24"
	call(plan, false, "unchanged")
	delete(args, "allowed_networks")
	args["action"] = "toggle"
	args["enabled"] = true
	args["dry_run"] = false
	call(revoke, true, "operator administration")
	delete(args, "dry_run")
	args["enabled"] = false
	call(revoke, false, "planned")
	if disables != 0 || reloads != 0 {
		t.Fatal("preview made a change")
	}
	deny = true
	call(revoke, true, "permission_denied")
	deny = false
	args["dry_run"] = false
	call(revoke, false, "service_running")
	call(revoke, false, "unchanged")
	if disables != 1 || reloads != 2 {
		t.Fatal(disables, reloads)
	}
	args["action"] = "remove"
	delete(args, "enabled")
	reloadFail = true
	call(revoke, true, "reload unconfirmed")
	if deletes != 1 {
		t.Fatal(deletes)
	}
	reloadFail = false
	call(revoke, false, "absent")
	if deletes != 1 {
		t.Fatal(deletes)
	}
}
