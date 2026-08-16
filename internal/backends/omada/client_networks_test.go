package omada

import (
	"testing"
)

// TestEnrichClients uses fixtures shaped like live 6.2.14 wire rows:
// clients carry ssid/vid but no networkName, and some wireless rows omit
// vid entirely.
func TestEnrichClients(t *testing.T) {
	networks := []Network{
		{Name: "LAN(Default)", SSID: "LAN", VLANID: 1},
		{Name: "Trusted", SSID: "Trusted", VLANID: 10},
		{Name: "IoT", SSID: "IoT", VLANID: 60},
	}

	clients := []ConnectedClient{
		// SSID match, vid absent (observed on live wireless rows).
		{Name: "Mac", IP: "10.0.0.110", SSID: "Trusted", Wireless: true},
		// SSID matches a default network's origName, not its display name.
		{Name: "Watch", IP: "10.0.0.138", SSID: "LAN", Wireless: true},
		// No SSID, vid present: wired client resolved by VLAN id.
		{Name: "OPNsense", IP: "10.0.0.100", VLANID: 1, Wireless: false},
		// Case-insensitive SSID match.
		{Name: "iPad", IP: "10.0.0.84", SSID: "trusted", Wireless: true},
		// Unmappable: unknown SSID and no vid.
		{Name: "Mystery", IP: "10.0.0.5", SSID: "UnknownNet", Wireless: true},
		// Controller that already reports a network name: untouched.
		{Name: "Legacy", IP: "10.0.0.9", SSID: "Trusted", VLANID: 10, NetworkName: "Trusted"},
	}

	EnrichClients(clients, networks)

	cases := []struct {
		index   int
		want    string
		wantVid int
	}{
		{0, "Trusted", 10},     // ssid → name, vid filled
		{1, "LAN(Default)", 1}, // ssid → origName network
		{2, "LAN(Default)", 1}, // vid only
		{3, "Trusted", 10},     // case-insensitive ssid
		{4, "", 0},             // unmapped
		{5, "Trusted", 10},     // pre-set name preserved
	}
	for _, tc := range cases {
		c := clients[tc.index]
		if c.NetworkName != tc.want {
			t.Errorf("client %d (%s): NetworkName = %q, want %q", tc.index, c.Name, c.NetworkName, tc.want)
		}
		if c.VLANID != tc.wantVid {
			t.Errorf("client %d (%s): VLANID = %d, want %d", tc.index, c.Name, c.VLANID, tc.wantVid)
		}
	}
}

func TestEnrichClients_NoNetworks(t *testing.T) {
	clients := []ConnectedClient{
		{Name: "Mac", IP: "10.0.0.1", SSID: "Trusted"},
	}
	EnrichClients(clients, nil)
	if clients[0].NetworkName != "" || clients[0].VLANID != 0 {
		t.Errorf("enriched without networks = %+v, want untouched", clients[0])
	}
}

func TestEnrichClients_EmptySSIDAndVLAN(t *testing.T) {
	// A client with neither SSID nor vid stays unmapped (the "" group).
	clients := []ConnectedClient{{Name: "X", IP: "10.0.0.1"}}
	EnrichClients(clients, []Network{{Name: "Trusted", SSID: "Trusted", VLANID: 10}})
	if clients[0].NetworkName != "" {
		t.Errorf("NetworkName = %q, want empty", clients[0].NetworkName)
	}
}

func TestClientNetworkIndex_Collisions(t *testing.T) {
	// First network wins on duplicate SSID keys or VLAN ids.
	networks := []Network{
		{Name: "First", SSID: "Shared", VLANID: 10},
		{Name: "Second", SSID: "Shared", VLANID: 10},
	}
	bySSID, byVLAN := clientNetworkIndex(networks)
	if bySSID["shared"].Name != "First" {
		t.Errorf("bySSID[shared] = %q, want First (first wins)", bySSID["shared"].Name)
	}
	if byVLAN[10].Name != "First" {
		t.Errorf("byVLAN[10] = %q, want First (first wins)", byVLAN[10].Name)
	}
	// The display name is also indexed ("Second" only via its name key).
	if _, ok := bySSID["second"]; !ok {
		t.Error("display name not indexed as SSID key")
	}
}
