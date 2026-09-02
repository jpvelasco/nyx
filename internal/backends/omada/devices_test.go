package omada

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// BDD S3.6 — devices live at sites/{id}/networks/devices and arrive in a
// paged envelope (a bare array is still accepted).
func TestGetDevicesFlatArray(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi/v1/abc123/sites/s1/networks/devices" {
			writeEnvelope(w, 0, "", `[
				{"id":"d1","name":"GW-CORE","model":"GW-CORE","type":"gateway","mac":"aa:bb:cc:dd:ee:00","ip":"10.0.0.254","firmwareVersion":"2.2.3","needUpgrade":true},
				{"id":"d2","name":"SW-2428P","model":"SW-2428P","type":"switch","mac":"aa:bb:cc:dd:ee:01","ip":"10.0.0.253","firmwareVersion":"1.1.15","needUpgrade":false},
				{"id":"d3","name":"AP-01","model":"EAP652","type":"ap","mac":"aa:bb:cc:dd:ee:02","ip":"10.0.0.252"}
			]`)
			return
		}
		t.Errorf("unexpected path %s", r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	devices, err := c.GetDevices(context.Background(), "s1")
	if err != nil {
		t.Fatalf("GetDevices: %v", err)
	}
	if len(devices) != 3 {
		t.Fatalf("devices = %d, want 3", len(devices))
	}
	if !devices[0].IsGateway() || devices[0].Name != "GW-CORE" || !devices[0].NeedUpgrade {
		t.Errorf("devices[0] = %+v", devices[0])
	}
	if !devices[1].IsSwitch() || !devices[2].IsAP() {
		t.Errorf("devices[1] = %+v, devices[2] = %+v", devices[1], devices[2])
	}
}

func TestGetDevicesPagedWrapper(t *testing.T) {
	var gotQuery string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi/v1/abc123/sites/s1/networks/devices" {
			gotQuery = r.URL.RawQuery
			writeEnvelope(w, 0, "", `{"totalRows":1,"currentPage":1,"currentSize":1,"data":[{"id":"d1","name":"GW-CORE","model":"GW-CORE","type":"gateway","mac":"aa:bb:cc:dd:ee:00","ip":"10.0.0.254"}]}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	devices, err := c.GetDevices(context.Background(), "s1")
	if err != nil {
		t.Fatalf("GetDevices: %v", err)
	}
	if len(devices) != 1 || devices[0].Name != "GW-CORE" {
		t.Errorf("devices = %+v, want 1 GW-CORE", devices)
	}
	if gotQuery != "page=1&pageSize=200" {
		t.Errorf("query = %q, want page/pageSize params", gotQuery)
	}
}

func TestGetDevicesErrors(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi/v1/abc123/sites/s1/networks/devices" {
			writeEnvelope(w, 0, "", `[{"id":"d1","name":123}]`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	// Malformed row payload must surface as a decode error.
	if _, err := c.GetDevices(context.Background(), "s1"); err == nil || !strings.Contains(err.Error(), "decoding paged list response") {
		t.Errorf("error = %v, want decode failure", err)
	}
	// Missing site must surface as the fetching wrapper.
	if _, err := c.GetDevices(context.Background(), "missing"); err == nil || !strings.Contains(err.Error(), "getting devices") {
		t.Errorf("error = %v, want getting devices", err)
	}
}

func TestGatewayForNetworkByMAC(t *testing.T) {
	nets := []Network{
		{ID: "n1", Name: "Trusted", DeviceMac: "aa:bb:cc:dd:ee:00"},
		{ID: "n2", Name: "IoT", DeviceMac: "aa:bb:cc:dd:ee:00"},
		{ID: "n3", Name: "Orphan"},
	}
	devices := []Device{
		{Name: "GW-CORE", Type: "gateway", MAC: "aa-bb-cc-dd-ee-00", IP: "10.0.0.254"},
		{Name: "SW-2428P", Type: "switch", MAC: "aa:bb:cc:dd:ee:01", IP: "10.0.0.253"},
	}
	gw := GatewayForNetwork(devices, nets, "n1")
	if gw == nil || gw.Name != "GW-CORE" {
		t.Errorf("GatewayForNetwork(n1) = %+v, want GW-CORE", gw)
	}
	// n3 has no deviceMac but the site has exactly one managed gateway, so
	// the single-gateway fallback binds it (see TestGatewayForNetworkSingleGatewayFallback).
	if gw := GatewayForNetwork(devices, nets, "n3"); gw == nil || gw.Name != "GW-CORE" {
		t.Errorf("GatewayForNetwork(n3) = %+v, want GW-CORE (single managed gateway)", gw)
	}

	gwMap := NetworkGatewayMap(devices, nets)
	if gwMap["Trusted"] != "GW-CORE" || gwMap["IoT"] != "GW-CORE" || gwMap["Orphan"] != "GW-CORE" {
		t.Errorf("NetworkGatewayMap = %v", gwMap)
	}
}

func TestGatewayForNetworkByIPFallback(t *testing.T) {
	// Omada 6.2.x serves lan-networks rows without deviceMac; the gateway
	// IP must then resolve the binding.
	nets := []Network{
		{ID: "n1", Name: "Trusted", GatewaySubnet: "10.0.0.1/24"},
		{ID: "n2", Name: "IoT", GatewaySubnet: "10.0.1.1/24"},
		{ID: "n3", Name: "Orphan", GatewaySubnet: "10.0.2.1/24"},
	}
	devices := []Device{
		{Name: "GW-CORE", Type: "gateway", MAC: "aa:bb:cc:dd:ee:00", IP: "10.0.0.1"},
		{Name: "GW-EDGE", Type: "gateway", MAC: "aa:bb:cc:dd:ee:03", IP: "10.0.1.1"},
		{Name: "SW-2428P", Type: "switch", MAC: "aa:bb:cc:dd:ee:01", IP: "10.0.0.253"},
	}
	if gw := GatewayForNetwork(devices, nets, "n1"); gw == nil || gw.Name != "GW-CORE" {
		t.Errorf("GatewayForNetwork(n1) = %+v, want GW-CORE via gateway IP", gw)
	}
	if gw := GatewayForNetwork(devices, nets, "n2"); gw == nil || gw.Name != "GW-EDGE" {
		t.Errorf("GatewayForNetwork(n2) = %+v, want GW-EDGE via gateway IP", gw)
	}
	// No binding and no gateway owns 10.0.2.1 — multi-gateway sites must
	// stay unbound rather than guessed.
	if gw := GatewayForNetwork(devices, nets, "n3"); gw != nil {
		t.Errorf("GatewayForNetwork(n3) = %+v, want nil (multi-gateway, no binding)", gw)
	}
	gwMap := NetworkGatewayMap(devices, nets)
	if gwMap["Trusted"] != "GW-CORE" || gwMap["IoT"] != "GW-EDGE" || gwMap["Orphan"] != "" {
		t.Errorf("NetworkGatewayMap = %v", gwMap)
	}
}

func TestGatewayForNetworkSingleGatewayFallback(t *testing.T) {
	// 6.2.x single-gateway site: lan-networks carry no deviceMac and a
	// managed gateway exposes only its management IP, never the per-VLAN
	// routed addresses. Every unbound LAN must resolve to the one managed
	// gateway — it is the only device inter-VLAN traffic can transit.
	nets := []Network{
		{ID: "n1", Name: "Trusted", GatewaySubnet: "10.0.0.1/24"},
		{ID: "n2", Name: "IoT", GatewaySubnet: "10.0.1.1/24"},
		{ID: "n3", Name: "Orphan"},
	}
	devices := []Device{
		{Name: "GW-CORE", Type: "gateway", MAC: "aa:bb:cc:dd:ee:00", IP: "10.0.0.254"},
		{Name: "SW-2428P", Type: "switch", MAC: "aa:bb:cc:dd:ee:01", IP: "10.0.0.253"},
	}
	for _, id := range []string{"n1", "n2", "n3"} {
		if gw := GatewayForNetwork(devices, nets, id); gw == nil || gw.Name != "GW-CORE" {
			t.Errorf("GatewayForNetwork(%s) = %+v, want GW-CORE (single managed gateway)", id, gw)
		}
	}
}

func TestGatewayForNetworkMACPreferredOverIP(t *testing.T) {
	// When both signals are present they must agree; a conflicting gateway
	// IP must not shadow the explicit deviceMac binding.
	nets := []Network{
		{ID: "n1", Name: "Trusted", DeviceMac: "aa:bb:cc:dd:ee:00", GatewaySubnet: "10.0.1.1/24"},
	}
	devices := []Device{
		{Name: "GW-CORE", Type: "gateway", MAC: "aa:bb:cc:dd:ee:00", IP: "10.0.0.254"},
		{Name: "GW-EDGE", Type: "gateway", MAC: "aa:bb:cc:dd:ee:03", IP: "10.0.1.1"},
	}
	if gw := GatewayForNetwork(devices, nets, "n1"); gw == nil || gw.Name != "GW-CORE" {
		t.Errorf("GatewayForNetwork(n1) = %+v, want GW-CORE (MAC beats IP)", gw)
	}
}

func TestNormalizeMAC(t *testing.T) {
	// Normalization is total: colons, spaces, and dashes all collapse to the
	// same canonical form, so mixed separators compare equal.
	cases := map[string]string{
		"aa:bb:cc:dd:ee:00": "aabbccddee00",
		"aa bb cc dd ee 00": "aabbccddee00",
		"aa-bb-cc-dd-ee-00": "aabbccddee00",
		"":                  "",
	}
	for in, want := range cases {
		if got := normalizeMAC(in); got != want {
			t.Errorf("normalizeMAC(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSortedDevices(t *testing.T) {
	in := []Device{
		{Name: "z-ap", Type: "ap"},
		{Name: "b-gw", Type: "GATEWAY"},
		{Name: "a-sw", Type: "switch"},
		{Name: "m-odd", Type: "mouse"},
	}
	out := SortedDevices(in)
	var got []string
	for _, d := range out {
		got = append(got, d.Name)
	}
	want := []string{"b-gw", "a-sw", "z-ap", "m-odd"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("SortedDevices = %v, want %v", got, want)
	}
	// The input slice must not be reordered in place.
	if in[0].Name != "z-ap" {
		t.Errorf("input mutated: %v", in)
	}
}

func TestFetchInventory(t *testing.T) {
	newClient := func(failDevices, failACLs, failClients bool) *Client {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/openapi/v1/abc123/sites/s1/lan-networks":
				// Open API wire shape: DHCP nested under "dhcpSettingsVO".
				writeEnvelope(w, 0, "", `{"totalRows":2,"data":[
					{"id":"n1","name":"Trusted","vlan":10,"purpose":"interface","gatewaySubnet":"10.0.0.1/24","deviceMac":"aa:bb:cc:dd:ee:00","dhcpSettingsVO":{"enable":true}},
					{"id":"n2","name":"IoT","vlan":20,"purpose":"interface","gatewaySubnet":"10.0.1.1/24","deviceMac":"aa:bb:cc:dd:ee:00","dhcpSettingsVO":{"enable":false}}
				]}`)
			case "/openapi/v1/abc123/sites/s1/networks/devices":
				if failDevices {
					writeEnvelope(w, -1, "boom", "null")
					return
				}
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"d1","name":"GW-CORE","model":"GW-CORE","type":"gateway","mac":"aa:bb:cc:dd:ee:00","ip":"10.0.0.254"}]}`)
			case "/openapi/v1/abc123/sites/s1/acls/osg-acls":
				if failACLs {
					writeEnvelope(w, -1, "boom", "null")
					return
				}
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"a1","description":"deny","status":true,"policy":0}]}`)
			case "/openapi/v1/abc123/sites/s1/acls/osw-acls":
				if failACLs {
					writeEnvelope(w, -1, "boom", "null")
					return
				}
				writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
			case "/openapi/v1/abc123/sites/s1/networks/client":
				if failClients {
					writeEnvelope(w, -1, "boom", "null")
					return
				}
				// Thin rows: the wire carries only mac/name/type; FetchInventory
				// must enrich from the DHCP user list.
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"mac":"aa","name":"PC-01","type":"wired"}]}`)
			case "/openapi/v1/abc123/sites/s1/setting/service/dhcp/user-list":
				if failClients {
					writeEnvelope(w, -1, "boom", "null")
					return
				}
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[
					{"ipAddress":"10.0.0.50","macAddress":"aa","name":"PC-01","netId":"n1","netName":"Trusted"}
				]}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		return c
	}

	t.Run("full snapshot", func(t *testing.T) {
		c := newClient(false, false, false)
		snap, err := c.FetchInventory(context.Background(), "s1")
		if err != nil {
			t.Fatalf("FetchInventory: %v", err)
		}
		if len(snap.Devices) != 1 || len(snap.Networks) != 2 || len(snap.Clients) != 1 {
			t.Errorf("counts = %d/%d/%d, want 1/2/1", len(snap.Devices), len(snap.Networks), len(snap.Clients))
		}
		// The wire carries no per-client networkName: FetchInventory must
		// resolve it from the DHCP user list (MAC join) and backfill the VLAN
		// from the netId -> LAN network match.
		nc := snap.Clients[0]
		if nc.IP != "10.0.0.50" || nc.NetworkName != "Trusted" || nc.VLANID != 10 {
			t.Errorf("client = %+v, want enriched IP/NetworkName/VLANID", nc)
		}
		if !snap.GatewayACLsOK || !snap.SwitchACLsOK {
			t.Errorf("scopes = gw %v sw %v, want both OK", snap.GatewayACLsOK, snap.SwitchACLsOK)
		}
		if len(snap.Warnings) != 0 {
			t.Errorf("warnings = %v, want none", snap.Warnings)
		}
		gw, ok := snap.GatewayForNetwork("n1")
		if !ok || gw != "GW-CORE" {
			t.Errorf("GatewayForNetwork(n1) = %q, %v; want GW-CORE", gw, ok)
		}
		if snap.ControllerVersion == "" {
			t.Error("ControllerVersion empty, want 6.4.5.1 from /api/info")
		}
		if snap.ControllerCategory != "advanced" {
			t.Errorf("ControllerCategory = %q, want advanced from /api/info", snap.ControllerCategory)
		}
	})

	t.Run("partial failures degrade to warnings", func(t *testing.T) {
		c := newClient(true, true, true)
		snap, err := c.FetchInventory(context.Background(), "s1")
		if err != nil {
			t.Fatalf("FetchInventory: %v, want nil (degraded snapshot)", err)
		}
		// With no clients fetched the DHCP enrichment also degrades to a
		// warning: 5 best-effort fetches in total.
		if len(snap.Warnings) != 5 {
			t.Errorf("warnings = %v, want 5 (devices, gateway ACLs, switch ACLs, clients, DHCP enrichment)", snap.Warnings)
		}
		if snap.GatewayACLsOK || snap.SwitchACLsOK {
			t.Error("failed ACL scopes must not be marked OK")
		}
		if len(snap.Devices) != 0 || len(snap.Clients) != 0 {
			t.Errorf("failed fetches must not yield data: devices %d clients %d", len(snap.Devices), len(snap.Clients))
		}
	})

	t.Run("networks failure is fatal", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeEnvelope(w, -1, "boom", "null")
		}))
		if _, err := c.FetchInventory(context.Background(), "s1"); err == nil {
			t.Error("FetchInventory with failing networks fetch must error")
		}
	})
}

func TestBuildSpecInventory(t *testing.T) {
	snap := &InventorySnapshot{
		ControllerVersion:  "6.4.5.1",
		ControllerCategory: "advanced",
		Devices:            []Device{{Name: "GW-CORE", Model: "GW-CORE", Type: "gateway", MAC: "aa:bb:cc:dd:ee:00", IP: "10.0.0.254", FirmwareVersion: "2.2.3", NeedUpgrade: true}},
		Networks:           []Network{{ID: "n1", Name: "Trusted", GatewaySubnet: "10.0.0.1/24", VLANID: 10, DeviceMac: "aa:bb:cc:dd:ee:00"}},
		GatewayACLs:        ACLList{Rules: []ACLRule{{}, {}}},
		GatewayACLsOK:      true,
		SwitchACLs:         ACLList{},
		SwitchACLsOK:       true,
		Clients:            []ConnectedClient{{MAC: "aa"}},
	}
	inv := BuildSpecInventory(snap)
	if inv.ControllerVersion != "6.4.5.1" {
		t.Errorf("ControllerVersion = %q", inv.ControllerVersion)
	}
	if inv.ControllerCategory != "advanced" {
		t.Errorf("ControllerCategory = %q, want advanced", inv.ControllerCategory)
	}
	if len(inv.Devices) != 1 || inv.Devices[0].Name != "GW-CORE" || inv.Devices[0].Type != "gateway" ||
		!inv.Devices[0].Upgrade || inv.Devices[0].Firmware != "2.2.3" {
		t.Errorf("devices = %+v", inv.Devices)
	}
	if len(inv.Devices[0].Networks) != 1 || inv.Devices[0].Networks[0] != "trusted" {
		t.Errorf("device networks = %v, want [trusted]", inv.Devices[0].Networks)
	}
	if inv.NetworkGateways["trusted"] != "GW-CORE" {
		t.Errorf("NetworkGateways = %v, want trusted → GW-CORE", inv.NetworkGateways)
	}
	if len(inv.ACLScopes) != 2 {
		t.Fatalf("ACLScopes = %+v, want 2", inv.ACLScopes)
	}
	gw, sw := inv.ACLScopes[0], inv.ACLScopes[1]
	if gw.Scope != "gateway" || gw.RuleCount != 2 {
		t.Errorf("gateway scope = %+v, want 2 rules", gw)
	}
	if sw.Scope != "switch" || sw.RuleCount != 0 {
		t.Errorf("switch scope = %+v, want 0 rules", sw)
	}
}

func TestBuildSpecInventoryGatewayIPFallback(t *testing.T) {
	// 6.2.x wire shape: lan-networks rows carry no deviceMac; the gateway
	// IP is the only binding evidence.
	snap := &InventorySnapshot{
		Devices:  []Device{{Name: "GW-CORE", Model: "GW-CORE", Type: "gateway", MAC: "aa:bb:cc:dd:ee:00", IP: "10.0.0.1", FirmwareVersion: "2.2.3"}},
		Networks: []Network{{ID: "n1", Name: "Trusted", GatewaySubnet: "10.0.0.1/24", VLANID: 10}},
	}
	inv := BuildSpecInventory(snap)
	if inv.NetworkGateways["trusted"] != "GW-CORE" {
		t.Errorf("NetworkGateways = %v, want trusted → GW-CORE via gateway IP", inv.NetworkGateways)
	}
	if len(inv.Devices[0].Networks) != 1 || inv.Devices[0].Networks[0] != "trusted" {
		t.Errorf("device networks = %v, want [trusted] via gateway IP", inv.Devices[0].Networks)
	}
	out := RenderInventory(snap, "HQ")
	if !strings.Contains(out, "gateway: GW-CORE") {
		t.Errorf("render must show the gateway device on the network row:\n%s", out)
	}
}

func TestBuildSpecInventoryOmitsFailedScopes(t *testing.T) {
	inv := BuildSpecInventory(&InventorySnapshot{
		Devices: []Device{},
	})
	if len(inv.Devices) != 0 || len(inv.ACLScopes) != 0 {
		t.Errorf("empty snapshot → devices %d scopes %d, want 0/0", len(inv.Devices), len(inv.ACLScopes))
	}
}

func TestRenderInventory(t *testing.T) {
	snap := &InventorySnapshot{
		ControllerVersion:  "6.4.5.1",
		ControllerCategory: "advanced",
		Devices:            []Device{{Name: "GW-CORE", Model: "GW-CORE", Type: "gateway", MAC: "aa:bb:cc:dd:ee:00", IP: "10.0.0.254", FirmwareVersion: "2.2.3", NeedUpgrade: true}},
		Networks:           []Network{{ID: "n1", Name: "Trusted", GatewaySubnet: "10.0.0.1/24", VLANID: 10, DeviceMac: "aa:bb:cc:dd:ee:00"}},
		GatewayACLs:        ACLList{Rules: []ACLRule{{}}},
		GatewayACLsOK:      true,
		SwitchACLs:         ACLList{},
		SwitchACLsOK:       true,
		Clients:            []ConnectedClient{{MAC: "aa"}, {MAC: "bb"}},
		Warnings:           []string{"clients unavailable: boom"},
	}
	out := RenderInventory(snap, "HQ")
	for _, want := range []string{
		"Site: HQ",
		"Controller: 6.4.5.1 (advanced)",
		"== Devices (1) ==",
		"GW-CORE",
		"2.2.3  [upgrade available]",
		"== Networks (1) ==",
		"gateway: GW-CORE",
		"== ACL scopes ==",
		"gateway: 1 rule",
		"switch:  0 rules",
		"== Clients ==",
		"2 active clients",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("render output missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "not enforced") {
		t.Errorf("render output must not claim stored rules are unenforced:\n%s", out)
	}
	// Warnings are owned by the CLI layer (stderr) and the JSON surface —
	// the renderer must not duplicate them (#60).
	if strings.Contains(out, "clients unavailable") {
		t.Errorf("render must not print warnings (CLI layer owns them):\n%s", out)
	}
}

func TestRenderInventoryNoCategory(t *testing.T) {
	snap := &InventorySnapshot{
		ControllerVersion: "6.4.5.1",
		Networks:          []Network{{ID: "n1", Name: "Trusted", GatewaySubnet: "10.0.0.1/24"}},
	}
	out := RenderInventory(snap, "HQ")
	if !strings.Contains(out, "Controller: 6.4.5.1\n") {
		t.Errorf("version without category must render bare:\n%s", out)
	}
	if strings.Contains(out, "Controller: 6.4.5.1 (") {
		t.Errorf("empty category must not render a parenthetical:\n%s", out)
	}
}

func TestRenderInventoryUnknownScopes(t *testing.T) {
	snap := &InventorySnapshot{
		Networks: []Network{{ID: "n1", Name: "Trusted", GatewaySubnet: "10.0.0.1/24"}},
	}
	out := RenderInventory(snap, "HQ")
	if !strings.Contains(out, "gateway: unknown (fetch failed)") || !strings.Contains(out, "switch:  unknown (fetch failed)") {
		t.Errorf("unknown scope rendering wrong:\n%s", out)
	}
	if !strings.Contains(out, "gateway: -") {
		t.Errorf("unbound network must render a dash:\n%s", out)
	}
}
