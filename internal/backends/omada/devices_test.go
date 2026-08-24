package omada

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestGetDevicesFlatArray(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi/authorize/token" {
			writeEnvelope(w, 0, "", `{"accessToken":"t1"}`)
			return
		}
		if r.URL.Path == "/abc123/openapi/v1/sites/s1/devices" {
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
	if err := c.Login(context.Background(), "admin", "pw"); err != nil {
		t.Fatalf("login: %v", err)
	}
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
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi/authorize/token" {
			writeEnvelope(w, 0, "", `{"accessToken":"t1"}`)
			return
		}
		if r.URL.Path == "/abc123/openapi/v1/sites/s1/devices" {
			writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"d1","name":"GW-CORE","model":"GW-CORE","type":"gateway","mac":"aa:bb:cc:dd:ee:00","ip":"10.0.0.254"}]}`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	if err := c.Login(context.Background(), "admin", "pw"); err != nil {
		t.Fatalf("login: %v", err)
	}
	devices, err := c.GetDevices(context.Background(), "s1")
	if err != nil {
		t.Fatalf("GetDevices: %v", err)
	}
	if len(devices) != 1 || devices[0].Name != "GW-CORE" {
		t.Errorf("devices = %+v, want 1 GW-CORE", devices)
	}
}

func TestGetDevicesErrors(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeEnvelope(w, 0, "", `{"accessToken":"t1"}`)
		case "/abc123/openapi/v1/sites/s1/devices":
			writeEnvelope(w, 0, "", `[{"id":"d1","name":123}]`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	if err := c.Login(context.Background(), "admin", "pw"); err != nil {
		t.Fatalf("login: %v", err)
	}
	if _, err := c.GetDevices(context.Background(), "s1"); err == nil || !strings.Contains(err.Error(), "decoding device inventory") {
		t.Errorf("error = %v, want decoding device inventory", err)
	}
	if _, err := c.GetDevices(context.Background(), "missing"); err == nil || !strings.Contains(err.Error(), "getting devices") {
		t.Errorf("error = %v, want getting devices", err)
	}
}

func TestNetworkBindingsAndGatewayForNetwork(t *testing.T) {
	nets := []Network{
		{ID: "n1", Name: "Trusted", DeviceMac: "aa:bb:cc:dd:ee:00"},
		{ID: "n2", Name: "IoT", DeviceMac: "aa:bb:cc:dd:ee:00"},
		{ID: "n3", Name: "Orphan"},
	}
	bindings := BuildNetworkBindings(nets)
	if len(bindings) != 2 || bindings["n1"] != "aa:bb:cc:dd:ee:00" {
		t.Errorf("bindings = %v", bindings)
	}
	devices := []Device{
		{Name: "GW-CORE", Type: "gateway", MAC: "aa-bb-cc-dd-ee-00"},
		{Name: "SW-2428P", Type: "switch", MAC: "aa:bb:cc:dd:ee:01"},
	}
	gw := GatewayForNetwork(devices, "n1", bindings)
	if gw == nil || gw.Name != "GW-CORE" {
		t.Errorf("GatewayForNetwork(n1) = %+v, want GW-CORE", gw)
	}
	if gw := GatewayForNetwork(devices, "n3", bindings); gw != nil {
		t.Errorf("GatewayForNetwork(n3) = %+v, want nil (unbound)", gw)
	}

	gwMap := NetworkGatewayMap(devices, nets, bindings)
	if gwMap["Trusted"] != "GW-CORE" || gwMap["IoT"] != "GW-CORE" || gwMap["Orphan"] != "" {
		t.Errorf("NetworkGatewayMap = %v", gwMap)
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
			case "/openapi/authorize/token":
				writeEnvelope(w, 0, "", `{"accessToken":"t1"}`)
			case "/abc123/openapi/v1/sites/s1/setting/lan/networks":
				// Live 6.x wire shape: DHCP nested under "dhcpSettings", SSID
				// as "origName" — no top-level dhcpEnabled or per-client
				// networkName on the wire.
				writeEnvelope(w, 0, "", `{"totalRows":2,"data":[
					{"id":"n1","name":"Trusted","vlan":10,"purpose":"interface","gatewaySubnet":"10.0.0.1/24","deviceMac":"aa:bb:cc:dd:ee:00","dhcpSettings":{"enable":true},"origName":"Trusted"},
					{"id":"n2","name":"IoT","vlan":20,"purpose":"interface","gatewaySubnet":"10.0.1.1/24","deviceMac":"aa:bb:cc:dd:ee:00","dhcpSettings":{"enable":false},"origName":"IoT"}
				]}`)
			case "/abc123/openapi/v1/sites/s1/devices":
				if failDevices {
					writeEnvelope(w, -1, "boom", "null")
					return
				}
				writeEnvelope(w, 0, "", `[{"id":"d1","name":"GW-CORE","model":"GW-CORE","type":"gateway","mac":"aa:bb:cc:dd:ee:00","ip":"10.0.0.254"}]`)
			case "/abc123/openapi/v1/sites/s1/setting/firewall/acls":
				if failACLs {
					writeEnvelope(w, -1, "boom", "null")
					return
				}
				if r.URL.Query().Get("type") == "0" {
					writeEnvelope(w, 0, "", `{"totalRows":1,"aclDisable":true,"supportLanToLan":true,"data":[{"id":"a1","name":"deny","status":true,"policy":0}]}`)
					return
				}
				writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
			case "/abc123/openapi/v1/sites/s1/clients":
				if failClients {
					writeEnvelope(w, -1, "boom", "null")
					return
				}
				// Live 6.x wire shape: no "networkName" field; the client only
				// reports its SSID (vid is often omitted), so FetchInventory
				// must resolve the network from the LAN list.
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"mac":"aa","ip":"10.0.0.50","ssid":"Trusted","wireless":true}]}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		if err := c.Login(context.Background(), "admin", "pw"); err != nil {
			t.Fatalf("login: %v", err)
		}
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
		// resolve it from the LAN networks (SSID match) and backfill the VLAN.
		nc := snap.Clients[0]
		if nc.NetworkName != "Trusted" || nc.VLANID != 10 {
			t.Errorf("client = %+v, want NetworkName Trusted, VLANID 10", nc)
		}
		if !snap.GatewayACLsOK || !snap.SwitchACLsOK {
			t.Errorf("scopes = gw %v sw %v, want both OK", snap.GatewayACLsOK, snap.SwitchACLsOK)
		}
		if !snap.GatewayACLs.ACLDisable || !snap.GatewayACLs.SupportLanToLan {
			t.Errorf("gateway flags = disable %v lan2lan %v, want true/true", snap.GatewayACLs.ACLDisable, snap.GatewayACLs.SupportLanToLan)
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
		if len(snap.Warnings) != 4 {
			t.Errorf("warnings = %v, want 4 (devices, gateway ACLs, switch ACLs, clients)", snap.Warnings)
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
			switch r.URL.Path {
			case "/openapi/authorize/token":
				writeEnvelope(w, 0, "", `{"accessToken":"t1"}`)
			default:
				writeEnvelope(w, -1, "boom", "null")
			}
		}))
		if err := c.Login(context.Background(), "admin", "pw"); err != nil {
			t.Fatalf("login: %v", err)
		}
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
		Bindings:           NetworkBindings{"n1": "aa:bb:cc:dd:ee:00"},
		GatewayACLs:        ACLList{ACLDisable: true, SupportLanToLan: true, Rules: []ACLRule{{}, {}}},
		GatewayACLsOK:      true,
		SwitchACLs:         ACLList{ACLDisable: false},
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
	if gw.Scope != "gateway" || gw.Enabled || gw.RuleCount != 2 {
		t.Errorf("gateway scope = %+v, want disabled/2 rules", gw)
	}
	if gw.SupportLanToLan == nil || !*gw.SupportLanToLan {
		t.Errorf("gateway SupportLanToLan = %v, want ptr(true)", gw.SupportLanToLan)
	}
	if sw.Scope != "switch" || !sw.Enabled || sw.RuleCount != 0 {
		t.Errorf("switch scope = %+v, want enabled/0 rules", sw)
	}
	if sw.SupportLanToLan != nil {
		t.Errorf("switch SupportLanToLan = %v, want nil (gateway-only)", sw.SupportLanToLan)
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
		Bindings:           NetworkBindings{"n1": "aa:bb:cc:dd:ee:00"},
		GatewayACLs:        ACLList{ACLDisable: true, SupportLanToLan: true, Rules: []ACLRule{{}}},
		GatewayACLsOK:      true,
		SwitchACLs:         ACLList{Rules: []ACLRule{}},
		SwitchACLsOK:       true,
		Clients:            []ConnectedClient{{MAC: "aa"}, {MAC: "bb"}},
		Warnings:           []string{"clients unavailable: boom"},
	}
	out := RenderInventory(snap, "HQ")
	for _, want := range []string{
		"Site: HQ",
		"Controller: 6.4.5.1 (advanced)",
		"Warning: clients unavailable: boom",
		"== Devices (1) ==",
		"GW-CORE",
		"2.2.3  [upgrade available]",
		"== Networks (1) ==",
		"gateway: GW-CORE",
		"== ACL scopes ==",
		"DISABLED — stored rules are not enforced",
		"(lan-to-lan supported)",
		"== Clients ==",
		"2 active clients",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("render output missing %q:\n%s", want, out)
		}
	}
	// Switch scope rendered enabled with no lan-to-lan suffix.
	if !strings.Contains(out, "switch:") || strings.Count(out, "(lan-to-lan supported)") != 1 {
		t.Errorf("switch scope rendering wrong:\n%s", out)
	}
	if !strings.Contains(out, "enabled") {
		t.Errorf("switch scope should render enabled:\n%s", out)
	}
}

func TestRenderInventoryNoCategory(t *testing.T) {
	snap := &InventorySnapshot{
		ControllerVersion: "6.4.5.1",
		Networks:          []Network{{ID: "n1", Name: "Trusted", GatewaySubnet: "10.0.0.1/24"}},
		Bindings:          NetworkBindings{},
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
		Bindings: NetworkBindings{},
	}
	out := RenderInventory(snap, "HQ")
	if !strings.Contains(out, "gateway: unknown (fetch failed)") || !strings.Contains(out, "switch:  unknown (fetch failed)") {
		t.Errorf("unknown scope rendering wrong:\n%s", out)
	}
	if !strings.Contains(out, "gateway: -") {
		t.Errorf("unbound network must render a dash:\n%s", out)
	}
}
