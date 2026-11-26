package mcp

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/service"
	"github.com/jpvelasco/nyx/internal/testutil"
)

func TestPeerPreviewAndRevocation(t *testing.T) {
	hermeticCreds(t)
	const id = "00000000-0000-4000-8000-a00000000001"
	const other = "00000000-0000-4000-8000-a00000000002"
	enabled, exists, deny, reloadFail := true, true, false, false
	disables, deletes, reloads := 0, 0, 0
	firewall, ca := testutil.CASignedServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	t.Setenv("OPNSENSE_HOST", strings.TrimPrefix(firewall, "https://"))
	t.Setenv("OPNSENSE_API_KEY", "fixture")
	t.Setenv("OPNSENSE_API_SECRET", "fixture-secret")
	t.Setenv("NYX_OPNSENSE_CA_CERT", ca)
	args := map[string]interface{}{}
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
	for _, name := range []string{plan, revoke} {
		fields := []string{"host", "api_secret"}
		if name == revoke {
			fields = append(fields, "skip_tls_verify", "ca_cert_path")
		}
		for _, field := range fields {
			args[field] = "other.example"
			call(name, true, "unsupported")
			delete(args, field)
		}
		args["profile"] = false
		call(name, true, "must be a string")
		args["profile"] = "unconfigured"
		call(name, true, "configure the selected")
		delete(args, "profile")
	}
	args["enabled"] = "no"
	call(revoke, true, "must be a boolean")
	delete(args, "enabled")
	args["dry_run"] = "no"
	call(revoke, true, "must be a boolean")
	delete(args, "dry_run")
	args["action"] = "create"
	args["name"] = "iot"
	args["allowed_networks"] = "10.0.11.0/24"
	call(plan, false, "overlap")
	t.Setenv("NYX_OPNSENSE_CA_CERT", "")
	call(plan, true, "unavailable")
	args["skip_tls_verify"] = true
	call(plan, false, "overlap")
	delete(args, "skip_tls_verify")
	args["ca_cert_path"] = ca
	call(plan, false, "overlap")
	delete(args, "ca_cert_path")
	call(plan, true, "unavailable")
	t.Setenv("NYX_OPNSENSE_CA_CERT", ca)
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

func TestApprovedPeerToolRejectsOverrides(t *testing.T) {
	hermeticCreds(t)
	s := NewServerWithLogger(nil)
	for _, args := range []map[string]interface{}{nil, {"dry_run": "false"}, {"public_key": "fixture"}, {"file": "other.json"}, {"host": "other.example"}} {
		if _, failed := s.dispatchTool(t.Context(), "opnsense_apply_approved_wireguard_peer", args); !failed {
			t.Fatal("accepted missing or overridden approval")
		}
	}
	file := filepath.Join(t.TempDir(), "approval.json")
	if err := os.WriteFile(file, []byte(`{"profile":"default"}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(service.PeerApprovalEnv, file)
	if out, failed := s.dispatchTool(t.Context(), "opnsense_apply_approved_wireguard_peer", nil); !failed || !strings.Contains(out, "configure the approved") {
		t.Fatal("unconfigured connection did not fail", out)
	}
	t.Setenv("OPNSENSE_HOST", "firewall.example")
	t.Setenv("OPNSENSE_API_KEY", "fixture")
	t.Setenv("OPNSENSE_API_SECRET", "fixture")
	if out, failed := s.dispatchTool(t.Context(), "opnsense_apply_approved_wireguard_peer", map[string]any{"dry_run": false}); !failed || !strings.Contains(out, "incomplete approved peer") {
		t.Fatal("incomplete grant did not fail before network access", out)
	}
}
