package service

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestApprovedPeerReconciliation(t *testing.T) {
	const peerID = "00000000-0000-4000-8000-a00000000001"
	const serverID = "00000000-0000-4000-8000-a00000000002"
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	saves := 0
	exists := false
	denied := false
	var selected map[string]string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if denied {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		enc := json.NewEncoder(w)
		switch r.URL.Path {
		case "/api/wireguard/client/search_client":
			rows := []map[string]string{}
			if exists {
				rows = append(rows, map[string]string{"uuid": peerID, "pubkey": key, "name": "trusted", "tunneladdress": selected["tunneladdress"], "enabled": selected["enabled"]})
			}
			_ = enc.Encode(map[string]any{"rows": rows, "total": len(rows)})
		case "/api/wireguard/server/search_server":
			_ = enc.Encode(map[string]any{"rows": []map[string]string{{"uuid": serverID, "name": "management"}}, "total": 1})
		case "/api/wireguard/client/add_client", "/api/wireguard/client/set_client/" + peerID:
			if r.Method != http.MethodPost {
				t.Error("incorrect method")
			}
			var data struct{ Client map[string]string }
			if json.NewDecoder(r.Body).Decode(&data) != nil || len(data.Client) != 5 || data.Client["pubkey"] != key || data.Client["servers"] != serverID {
				t.Error("unexpected fields sent")
			}
			saves++
			exists = true
			selected = data.Client
			_ = enc.Encode(map[string]string{"result": "saved", "uuid": peerID})
		case "/api/wireguard/client/get_client/" + peerID:
			_ = enc.Encode(map[string]any{"client": map[string]any{"pubkey": key, "name": "trusted", "enabled": selected["enabled"], "servers": map[string]any{serverID: map[string]int{"selected": 1}}, "tunneladdress": map[string]any{selected["tunneladdress"]: map[string]int{"selected": 1}}, "psk": "fixture-secret"}})
		case "/api/wireguard/service/reconfigure":
			_ = enc.Encode(map[string]string{"result": "ok"})
		case "/api/wireguard/service/status":
			_ = enc.Encode(map[string]string{"status": "running"})
		default:
			t.Error("unexpected endpoint")
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "https://")
	on := true
	a := ApprovedPeer{Profile: "default", Host: host, Name: "trusted", PublicKey: key, Enabled: &on, Servers: []string{serverID}, AllowedNetworks: []string{"10.0.10.0/24"}}
	opts := OpnsenseOptions{Host: host, SkipTLSVerify: true}
	svc := NewOpnsenseService()
	run := func(dry bool, want string, writes int) {
		t.Helper()
		res, err := svc.ApplyApprovedPeer(t.Context(), opts, a, dry)
		if err != nil || res.Outcome != want || saves != writes {
			t.Fatalf("result %+v, %v", res, err)
		}
		out, _ := json.Marshal(res)
		if strings.Contains(string(out), key) || strings.Contains(string(out), "fixture-secret") {
			t.Fatal("key leak")
		}
	}
	run(true, "planned", 0)
	run(false, "applied", 1)
	run(false, "unchanged", 1)
	a.UUID = peerID
	a.AllowedNetworks = []string{"10.0.20.0/24"}
	run(false, "applied", 2)
	on = false
	run(false, "applied", 3)
	on = true
	run(false, "applied", 4)
	a.PublicKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	if _, err := svc.ApplyApprovedPeer(t.Context(), opts, a, false); err == nil || saves != 4 {
		t.Fatal("accepted conflicting identity")
	}
	denied = true
	if _, err := svc.ApplyApprovedPeer(t.Context(), opts, a, false); err == nil {
		t.Fatal("accepted private read failure")
	}
}
func TestApprovedPeerFileBoundary(t *testing.T) {
	file := filepath.Join(t.TempDir(), "peer.json")
	for _, s := range []string{`{"private_key":"fixture"}`, `{} {}`, `broken`} {
		if err := os.WriteFile(file, []byte(s), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadApprovedPeer(file); err == nil {
			t.Fatal("malformed approval accepted")
		}
	}
	if _, err := LoadApprovedPeer(file + ".missing"); err == nil {
		t.Fatal("accepted nonexisting local approval")
	}
}

func TestPeerPlanValidationAndOverlaps(t *testing.T) {
	const id = "00000000-0000-4000-8000-a00000000001"
	const other = "00000000-0000-4000-8000-a00000000002"
	yes, no := true, false
	f := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"rows":[{"uuid":"` + id + `","name":"trusted","enabled":"1","tunneladdress":"10.0.10.0/24"},{"uuid":"` + other + `","name":"management","enabled":"0","tunneladdress":"10.0.11.0/24"}],"total":2}`))
	}))
	defer f.Close()
	svc := NewOpnsenseService()
	opts := OpnsenseOptions{Host: strings.TrimPrefix(f.URL, "https://"), SkipTLSVerify: true}
	for _, r := range []WireGuardPeerRequest{{Action: "missing"}, {Action: "create"}, {Action: "update", UUID: "invalid"}, {Action: "update", UUID: id}, {Action: "toggle", UUID: id}, {Action: "remove", UUID: id, Name: "other"}, {Action: "create", Name: "other", AllowedNetworks: []string{"invalid"}}, {Action: "update", UUID: id, AllowedNetworks: []string{"10.0.10.0/24"}, Enabled: &no}, {Action: "create", Name: "trusted", AllowedNetworks: []string{"10.0.10.0/24"}}} {
		if _, err := svc.PlanWireGuardPeer(t.Context(), opts, r); err == nil {
			t.Fatalf("accepted invalid %s", r.Action)
		}
	}
	for _, tc := range []struct {
		req WireGuardPeerRequest
		out string
	}{{WireGuardPeerRequest{Action: "update", UUID: id, AllowedNetworks: []string{"10.0.10.0/24,10.0.10.0/24"}}, "unchanged"}, {WireGuardPeerRequest{Action: "update", UUID: id, AllowedNetworks: []string{"10.0.11.0/24"}}, "overlap"}, {WireGuardPeerRequest{Action: "toggle", UUID: id, Enabled: &yes}, "unchanged"}, {WireGuardPeerRequest{Action: "remove", UUID: "00000000-0000-4000-8000-a00000000003"}, "absent"}} {
		p, err := svc.PlanWireGuardPeer(t.Context(), opts, tc.req)
		if err != nil || p.Outcome != tc.out {
			t.Fatal(p, err)
		}
	}
}
