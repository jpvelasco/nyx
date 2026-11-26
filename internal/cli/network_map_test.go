package cli

import (
	"context"
	"encoding/json"
	"errors"
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
	omadaprovider "github.com/jpvelasco/nyx/internal/providers/omada"
	"github.com/jpvelasco/nyx/internal/providers/opnsense"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/jpvelasco/nyx/internal/testutil"
	"github.com/jpvelasco/nyx/internal/testutil/providerfixture"
	"github.com/jpvelasco/nyx/internal/topology"
)

type fixtureMapAdapter struct{}

func (fixtureMapAdapter) Name() string           { return "fixture-map" }
func (fixtureMapAdapter) Capabilities() []string { return []string{providers.NetworkMapCapability} }
func (fixtureMapAdapter) ObserveNetwork(_ context.Context, opts providers.ImportOptions) (topology.ObservationSet, error) {
	if opts.Host != "switch.example" {
		return topology.ObservationSet{}, errors.New("unexpected selected host")
	}
	ref := topology.ResourceRef{Kind: "switch", Key: "fixture-switch"}
	return topology.ObservationSet{Resources: []topology.Observation{{Ref: ref}}, Links: []topology.LinkObservation{{From: ref, To: topology.MapTarget{MAC: "02:aa:bb:cc:dd:01"}, Relation: "neighbor", Evidence: "LLDP"}}}, nil
}

func configureMapFixtures(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credentials.json")
	clearTopoEnv(t)
	t.Setenv("NYX_CREDENTIALS_FILE", path)
	providerfixture.IsolateProviders(t)
	for _, p := range []providers.Adapter{&omadaprovider.OmadaProvider{}, &opnsense.Provider{}, fixtureMapAdapter{}} {
		if err := providers.Register(p); err != nil {
			t.Fatal(err)
		}
	}
	omada := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/info" {
			testutil.WriteBody(w, `{"errorCode":0,"result":{"controllerVer":"6.3.0","apiVer":"2.0","omadacId":"fixture-controller","configured":true}}`)
			return
		}
		envelope := func(result string) { testutil.WriteBody(w, `{"errorCode":0,"result":`+result+`}`) }
		if r.Method != http.MethodGet && r.URL.Path != "/openapi/authorize/token" && !strings.HasSuffix(r.URL.Path, "/devices/uplink-info") {
			t.Errorf("unexpected Omada method %s", r.Method)
		}
		switch strings.TrimPrefix(r.URL.Path, "/openapi/v1/fixture-controller/sites/s1/") {
		case "/openapi/authorize/token":
			envelope(`{"accessToken":"tok"}`)
		case "/openapi/v1/fixture-controller/sites":
			envelope(`[{"id":"s1","name":"fixture-site"}]`)
		case "networks/devices":
			envelope(`[{"type":"switch","mac":"02:aa:bb:cc:dd:02"},{"type":"ap","mac":"02:aa:bb:cc:dd:03"}]`)
		case "switches/02-aa-bb-cc-dd-02/lldp-neighbors":
			envelope(`[{"portId":1,"deviceId":"02:aa:bb:cc:dd:01"}]`)
		case "devices/uplink-info":
			envelope(`[{"mac":"02:aa:bb:cc:dd:03","uplinkDeviceMac":"02:aa:bb:cc:dd:02","uplinkDevicePort":"8"}]`)
		case "lan-networks":
			envelope(`[{"id":"gaming","vlan":30,"gatewaySubnet":"10.0.30.1/24"},{"id":"management","vlan":11}]`)
		case "lan-profiles":
			envelope(`[{"id":"ap-profile","nativeNetworkId":"management","tagNetworkIds":["gaming"]}]`)
		case "switches/ports/overview":
			envelope(`[{"port":1,"switchMac":"02:aa:bb:cc:dd:02","profileOverrideEnable":true},{"port":8,"switchMac":"02:aa:bb:cc:dd:02","profileId":"ap-profile","portStatus":{"stpDiscarding":false}}]`)
		case "ssids":
			envelope(`[{"id":"gaming-wifi","ssid":"gaming","vlanId":30}]`)
		default:
			t.Errorf("unexpected Omada route %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(omada.Close)
	firewall := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if user, secret, ok := r.BasicAuth(); !ok || user != "key1" || secret != "secret1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet {
			t.Errorf("unexpected firewall method %s", r.Method)
		}
		switch r.URL.Path {
		case "/api/interfaces/vlan_settings/search_item":
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"gaming-zone","if":"igb0","vlanif":"vlan30","tag":"30"}]}`)
		case "/api/interfaces/overview/interfaces_info":
			testutil.WriteBody(w, `{"rows":[{"identifier":"lan","device":"igb0","link_type":"ether","macaddr":"02:aa:bb:cc:dd:01","enabled":true},{"identifier":"opt1","device":"vlan30","addr4":"10.0.30.1/24","enabled":true}]}`)
		default:
			t.Errorf("unexpected firewall route %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(firewall.Close)
	store, err := credentials.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for name, entry := range map[string]credentials.Entry{
		"omada":       {"host": omada.URL, "client_id": "fixture", "client_secret": "fixture", "site": "fixture-site"},
		"opnsense":    {"host": firewall.URL, "api_key": "key1", "api_secret": "secret1"},
		"fixture-map": {"host": "switch.example"},
	} {
		entry["logical_site"] = "shared"
		if err := store.Set(name, "home", entry); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNetworkMapCLIAndMCP(t *testing.T) {
	configureMapFixtures(t)
	oldOutput := outputPath
	t.Cleanup(func() { outputPath = oldOutput })
	outputPath = filepath.Join(t.TempDir(), "map.json")
	cmd := newNetworkMapCmd()
	cmd.SetContext(t.Context())
	cmd.SetArgs([]string{"--skip-tls-verify"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	var m topology.NetworkMap
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	text, failed := mcp.NewServerWithLogger(nil).DispatchToolForTest(t.Context(), service.NetworkMapTool, map[string]any{"skip_tls_verify": true})
	var envelope struct {
		Data      topology.NetworkMap `json:"data"`
		Untrusted bool                `json:"untrusted_data"`
	}
	if failed || json.Unmarshal([]byte(text), &envelope) != nil || !envelope.Untrusted || !reflect.DeepEqual(m, envelope.Data) {
		t.Fatalf("CLI/MCP map mismatch; MCP success=%t", !failed)
	}
	if len(m.Sources) != 3 || m.Sources[0].Site != m.Sources[1].Site || m.Sources[1].Site != m.Sources[2].Site {
		t.Fatalf("unexpected sources %+v", m.Sources)
	}
	counts := map[string]int{}
	for _, l := range m.Links {
		counts[l.Relation+"/"+l.State]++
	}
	for key, n := range map[string]int{"neighbor/observed": 2, "uplink/observed": 1, "gateway/observed": 1, "gateway/inferred": 1, "gateway/missing": 1, "native/observed": 1, "tagged/observed": 1, "segment/observed": 1} {
		if counts[key] != n {
			t.Errorf("%s = %d, want %d; links %+v", key, counts[key], n, m.Links)
		}
	}
	for _, row := range m.Resources {
		if row.Port == 8 && (row.STPDiscarding == nil || *row.STPDiscarding) {
			t.Error("missing reported forwarding state")
		}
		if row.Port == 1 && row.STPDiscarding != nil {
			t.Error("unreported STP was marked known")
		}
	}
	if !slices.Contains(m.Sources[1].Gaps, "effective tagged VLANs") {
		t.Error("unknown override membership must appear in gaps")
	}
}

func TestNetworkMapSelectionErrors(t *testing.T) {
	configureMapFixtures(t)
	topo := service.NewTopologyService()
	m, err := topo.Map(t.Context(), service.NetworkMapOptions{Connections: []string{"opnsense/absent", "opnsense/absent"}})
	if err != nil || len(m.Sources) != 1 || !slices.Contains(m.Sources[0].Gaps, "missing_credentials") {
		t.Fatalf("missing profile: %+v, %v", m, err)
	}
	for _, bad := range []string{"/home", "omada/", "unregistered/private"} {
		if _, err := topo.Map(t.Context(), service.NetworkMapOptions{Connections: []string{bad}}); err == nil {
			t.Error("accepted invalid selector")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := topo.Map(ctx, service.NetworkMapOptions{Connections: []string{"omada/home"}}); !errors.Is(err, context.Canceled) {
		t.Errorf("canceled map: %v", err)
	}
}
