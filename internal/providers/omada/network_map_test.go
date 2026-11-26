package omadaprovider

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/topology"
)

func TestObserveNetworkPartialCollections(t *testing.T) {
	const sw = "02:aa:bb:cc:dd:02"
	const ap = "02:aa:bb:cc:dd:03"
	failed := ""
	ts := omadaServer(t, func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/openapi/v1/abc123/sites/s1/")
		if path == failed {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var rows string
		switch path {
		case "/openapi/authorize/token":
			rows = `{"accessToken":"token"}`
		case "/openapi/v1/abc123/sites":
			rows = `[{"id":"s1","name":"fixture"}]`
		case "networks/devices":
			rows = `[{"type":"switch","mac":"` + sw + `"},{"type":"ap","mac":"` + ap + `"},{"type":"gateway","mac":"02:aa:bb:cc:dd:01"},{"type":"other","mac":"02:aa:bb:cc:dd:09"},{"type":"ap"}]`
		case "switches/02-aa-bb-cc-dd-02/lldp-neighbors":
			rows = `[{"portId":8,"deviceId":"` + ap + `"}]`
		case "devices/uplink-info":
			rows = `[{"mac":"` + ap + `","uplinkDeviceMac":"` + sw + `","uplinkDevicePort":"8"}]`
		case "lan-networks":
			rows = `[{"id":"management","vlan":11,"deviceMac":"02:aa:bb:cc:dd:01"},{"id":"gaming","vlan":30,"gatewaySubnet":"10.0.30.1/24"}]`
		case "lan-profiles":
			rows = `[{"id":"p1","nativeNetworkId":"management","tagNetworkIds":["gaming"]}]`
		case "switches/ports/overview":
			rows = `[{"port":8,"switchMac":"` + sw + `","profileId":"p1"},{"port":9,"switchMac":"` + sw + `","profileOverrideEnable":true,"nativeBridgeVlan":30}]`
		case "ssids":
			rows = `[{"id":"w1","ssid":"gaming","vlanId":30}]`
		default:
			t.Errorf("unexpected fixture route")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeEnvelope(w, 0, "", rows)
	})
	p := &OmadaProvider{}
	opts := providers.ImportOptions{Host: ts.URL, ClientID: "client", ClientSecret: "secret", SkipTLSVerify: true}
	for _, fail := range []string{"", "ssids", "networks/devices", "lan-profiles"} {
		failed = fail
		facts, err := p.ObserveNetwork(t.Context(), opts)
		if err != nil || facts.ControllerSite != "fixture" {
			t.Fatalf("observation: %v", err)
		}
		m := topology.BuildNetworkMap([]topology.MapInput{{Provider: "omada", Facts: facts}}, true)
		if len(m.Resources) < 4 || len(m.Links) < 4 {
			t.Fatalf("partial collection discarded remaining evidence")
		}
		if fail == "ssids" && !slices.Contains(facts.Gaps, "SSIDs") {
			t.Fatal("missing SSID outage")
		}
		if fail == "lan-profiles" && !slices.Contains(facts.Gaps, "effective tagged VLANs") {
			t.Fatal("unknown membership not recorded")
		}
		if fail == "" && (!slices.Contains(facts.Gaps, "device identity") || len(facts.Resources) != 9) {
			t.Fatalf("bad resources: %d, gaps %v", len(facts.Resources), facts.Gaps)
		}
	}
}
