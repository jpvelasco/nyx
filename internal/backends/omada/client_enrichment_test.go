package omada

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// BDD S3.5 — thin client rows are enriched from the DHCP user list
// (setting/service/dhcp/user-list), joined on the normalized MAC. A hit
// fills IP + network name + VLAN id (via netId -> the site's LAN networks).
func TestEnrichFromDHCP_HitAndMiss(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/abc123/openapi/v1/sites/s1/setting/service/dhcp/user-list" {
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeEnvelope(w, 0, "", `{"totalRows":2,"data":[
			{"ipAddress":"10.0.0.50","macAddress":"AA:BB:CC:DD:EE:01","name":"PC-01","netId":"n1","netName":"Trusted"},
			{"ipAddress":"10.0.1.50","macAddress":"aa-bb-cc-dd-ee-02","name":"NAS-01","netId":"n2","netName":"IoT"}
		]}`)
	}))
	clients := []ConnectedClient{
		{MAC: "aa:bb:cc:dd:ee:01", Name: "PC-01", Type: "wired"},
		{MAC: "aa:bb:cc:dd:ee:02", Name: "NAS-01", Type: "wired"},
		{MAC: "aa:bb:cc:dd:ee:03", Name: "Mystery", Type: "wired"},
	}
	networks := []Network{
		{ID: "n1", Name: "Trusted", VLANID: 10},
		{ID: "n2", Name: "IoT", VLANID: 20},
	}
	if err := c.EnrichFromDHCP(context.Background(), "s1", clients, networks); err != nil {
		t.Fatalf("EnrichFromDHCP: %v", err)
	}
	if clients[0].IP != "10.0.0.50" || clients[0].NetworkName != "Trusted" || clients[0].VLANID != 10 {
		t.Errorf("client 0 = %+v, want IP/name/VLAN from the DHCP row", clients[0])
	}
	if clients[1].IP != "10.0.1.50" || clients[1].NetworkName != "IoT" || clients[1].VLANID != 20 {
		t.Errorf("client 1 = %+v, want IP/name/VLAN from the DHCP row", clients[1])
	}
	// No DHCP row for this MAC: thin fields stay, no IP is invented.
	if clients[2].IP != "" || clients[2].NetworkName != "" || clients[2].VLANID != 0 {
		t.Errorf("client 2 = %+v, want untouched thin client", clients[2])
	}
}

func TestEnrichFromDHCP_UnknownNetIDFallsBackToNetName(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, 0, "", `{"totalRows":1,"data":[
			{"ipAddress":"10.0.2.50","macAddress":"aa:bb:cc:dd:ee:01","name":"PC-01","netId":"n9","netName":"Guest"}
		]}`)
	}))
	clients := []ConnectedClient{{MAC: "aa:bb:cc:dd:ee:01", Name: "PC-01"}}
	if err := c.EnrichFromDHCP(context.Background(), "s1", clients, []Network{{ID: "n1", Name: "Trusted", VLANID: 10}}); err != nil {
		t.Fatalf("EnrichFromDHCP: %v", err)
	}
	if clients[0].IP != "10.0.2.50" || clients[0].NetworkName != "Guest" || clients[0].VLANID != 0 {
		t.Errorf("client = %+v, want netName fallback and VLANID 0", clients[0])
	}
}

func TestEnrichFromDHCP_EmptyUserList(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
	}))
	clients := []ConnectedClient{{MAC: "aa:bb:cc:dd:ee:01", Name: "PC-01"}}
	if err := c.EnrichFromDHCP(context.Background(), "s1", clients, []Network{{ID: "n1", Name: "Trusted", VLANID: 10}}); err != nil {
		t.Fatalf("EnrichFromDHCP: %v", err)
	}
	if clients[0].IP != "" || clients[0].NetworkName != "" {
		t.Errorf("client = %+v, want untouched with an empty user list", clients[0])
	}
}

func TestEnrichFromDHCPFetchErrorPropagates(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, -1, "boom", "null")
	}))
	err := c.EnrichFromDHCP(context.Background(), "s1", nil, nil)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "dhcp") {
		t.Errorf("error = %v, want typed DHCP fetch error", err)
	}
}
