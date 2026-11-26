package cli

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"github.com/jpvelasco/nyx/internal/mcp"
	"github.com/jpvelasco/nyx/internal/service"
	"net/http"
	"os"
	"path/filepath"

	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
)

func TestPeerCommandDryRun(t *testing.T) {
	saveRestoreGlobals(t)
	clearProviderEnv(t)
	const id = "00000000-0000-4000-8000-a00000000001"
	calls := 0
	firewall := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/wireguard/client/search_client" {
			t.Error("unexpected mutation")
			http.NotFound(w, r)
			return
		}
		calls++
		testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"`+id+`","name":"trusted","enabled":"1","tunneladdress":"10.0.10.0/24"}]}`)
	}))
	defer firewall.Close()
	for _, apply := range []bool{false, true} {
		cmd := opnsensePeerCommand(apply)
		cmd.SetArgs([]string{"--host", strings.TrimPrefix(firewall.URL, "https://"), "--api-key", "fixture", "--api-secret", "fixture-secret", "--skip-tls-verify", "--uuid", id, "--action", "remove"})
		out := captureStdout(func() {
			if err := cmd.Execute(); err != nil {
				t.Fatal(err)
			}
		})
		if !strings.Contains(out, "planned") {
			t.Fatal(out)
		}
	}
	if calls != 2 {
		t.Fatal(calls)
	}
}

func TestApprovedPeerBothTransports(t *testing.T) {
	const serverID = "00000000-0000-4000-8000-a00000000002"
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/wireguard/client/search_client":
			testutil.WriteBody(w, `{"rows":[],"total":0}`)
		case "/api/wireguard/server/search_server":
			testutil.WriteBody(w, `{"rows":[{"uuid":"`+serverID+`"}],"total":1}`)
		default:
			t.Error("unexpected mutation")
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "fixture.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	on := true
	host := strings.TrimPrefix(ts.URL, "https://")
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	approved := service.ApprovedPeer{Profile: "default", CACertPath: ca, Host: host, Name: "trusted", PublicKey: key, Servers: []string{serverID}, AllowedNetworks: []string{"10.0.10.0/24"}, Enabled: &on}
	b, err := json.Marshal(approved)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(dir, "approval.json")
	if err := os.WriteFile(file, b, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(service.PeerApprovalEnv, file)
	t.Setenv("OPNSENSE_HOST", host)
	t.Setenv("OPNSENSE_API_KEY", "fixture")
	t.Setenv("OPNSENSE_API_SECRET", "fixture-secret")
	t.Setenv("NYX_CREDENTIALS_FILE", filepath.Join(dir, "store.json"))
	cmd := approvedPeerCommand()
	cmd.SetArgs(nil)
	var callErr error
	out := captureStdout(func() { callErr = cmd.ExecuteContext(t.Context()) })
	if callErr != nil || !strings.Contains(out, "planned") || strings.Contains(out, key) {
		t.Fatal(out, callErr)
	}
	rpc := mcp.NewServerWithLogger(nil)
	out, failed := rpc.DispatchToolForTest(t.Context(), "opnsense_apply_approved_wireguard_peer", nil)
	if failed || !strings.Contains(out, "planned") || strings.Contains(out, key) {
		t.Fatal(out)
	}

}
