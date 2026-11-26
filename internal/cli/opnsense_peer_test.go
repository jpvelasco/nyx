package cli

import (
	"net/http"
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
