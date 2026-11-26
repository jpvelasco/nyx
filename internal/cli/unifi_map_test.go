package cli

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/credentials"
	"github.com/jpvelasco/nyx/internal/mcp"
	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/providers/unifi"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/jpvelasco/nyx/internal/testutil"
	"github.com/jpvelasco/nyx/internal/topology"
)

func TestUniFiSwitchAndOPNsenseRouterMap(t *testing.T) {
	configureMapFixtures(t)
	if err := providers.Register(unifi.Adapter{}); err != nil {
		t.Fatal(err)
	}
	const id = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	const device = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
	const prefix = "/proxy/network/integration/v1/sites"
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("X-API-Key") != "fixture" {
			t.Error("unexpected UniFi request")
			return
		}
		switch r.URL.Path {
		case prefix:
			testutil.WriteBody(w, `{"offset":0,"count":1,"totalCount":1,"data":[{"id":"`+id+`","name":"site.example"}]}`)
		case prefix + "/" + id + "/devices":
			testutil.WriteBody(w, `{"offset":0,"count":1,"totalCount":1,"data":[{"id":"`+device+`","name":"switch.example","features":["switching"]}]}`)
		case prefix + "/" + id + "/devices/" + device:
			testutil.WriteBody(w, `{"id":"`+device+`","interfaces":{"ports":[{"idx":1}]}}`)
		default:
			t.Error("unexpected UniFi path")
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(s.Close)
	store, err := credentials.Open(os.Getenv("NYX_CREDENTIALS_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set("unifi", "home", credentials.Entry{"host": s.URL, "api_key": "fixture", "logical_site": "shared"}); err != nil {
		t.Fatal(err)
	}
	old := outputPath
	t.Cleanup(func() { outputPath = old })
	fixtureDir := t.TempDir()
	outputPath = filepath.Join(fixtureDir, "map.json")
	cmd := newNetworkMapCmd()
	cmd.SetContext(t.Context())
	cmd.SetArgs([]string{"--connection", "unifi/home", "--connection", "opnsense/home", "--skip-tls-verify"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	raw, err := fs.ReadFile(os.DirFS(fixtureDir), "map.json")
	if err != nil {
		t.Fatal(err)
	}
	var cliMap topology.NetworkMap
	if err := json.Unmarshal(raw, &cliMap); err != nil {
		t.Fatal(err)
	}
	text, failed := mcp.NewServerWithLogger(nil).DispatchToolForTest(t.Context(), service.NetworkMapTool, map[string]any{"connections": []any{"unifi/home", "opnsense/home"}, "skip_tls_verify": true})
	var result struct {
		Data      topology.NetworkMap
		Untrusted bool `json:"untrusted_data"`
	}
	if failed || json.Unmarshal([]byte(text), &result) != nil || !result.Untrusted || !reflect.DeepEqual(cliMap, result.Data) {
		t.Fatalf("CLI/MCP mismatch; MCP error %t", failed)
	}
	if len(cliMap.Sources) != 2 || cliMap.Sources[0].Site != cliMap.Sources[1].Site || !slices.Contains(cliMap.Sources[1].Gaps, "external link neighbors") {
		t.Fatalf("missing owners or evidence gaps: %+v", cliMap.Sources)
	}
	kinds := map[string]bool{}
	for _, row := range cliMap.Resources {
		kinds[row.Kind] = true
	}
	if !kinds["switch"] || !kinds["port"] || !kinds["gateway"] {
		t.Errorf("missing map resources: %v", kinds)
	}
	for _, v := range []string{id, device, "switch.example", "site.example", s.URL} {
		if strings.Contains(text, v) {
			t.Error("private value in default map")
		}
	}
}
