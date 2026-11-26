package omada

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// BDD S3.5 — thin client rows are enriched from the DHCP user list
// (setting/service/dhcp/user-list), joined on the normalized MAC. A hit
// fills IP + network name + VLAN id (via netId -> the site's LAN networks).
func TestEnrichFromDHCP_HitAndMiss(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/openapi/v1/abc123/sites/s1/setting/service/dhcp/user-list" {
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

func TestGetClientTopology(t *testing.T) {
	var method, path string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		writeEnvelope(w, 0, "", `[
			{"nodeType":"clientNode","clientNode":{"mac":"aa-bb-cc-dd-ee-01","name":"pc1","clientType":"wired","upOswInfo":{"mac":"aa-bb-cc-dd-ee-10","name":"SW-CORE","port":"8","linkSpeed":3}}},
			{"nodeType":"deviceNode","deviceNode":{"mac":"aa-bb-cc-dd-ee-10","name":"SW-CORE","model":"SW","switchInfo":{"mac":"aa-bb-cc-dd-ee-10","name":"SW-CORE","port":"1"}}},
			{"nodeType":1,"clientNode":{"name":"client","upOswInfo":{"port":8},"upApInfo":{"radio":0}}},
			{"nodeType":0,"deviceNode":{"name":"switch"},"clientNode":{"mac":"unused"}},
			{"nodeType":99}
		]`)
	}))
	nodes, err := c.GetClientTopology(context.Background(), "s1", "aa:bb:cc:dd:ee:01")
	if err != nil {
		t.Fatalf("GetClientTopology: %v", err)
	}
	if method != http.MethodPost {
		t.Errorf("method = %s, want POST", method)
	}
	if path != "/openapi/v1/abc123/sites/s1/clients/aa-bb-cc-dd-ee-01/client-link-topology" {
		t.Errorf("path = %s", path)
	}
	if len(nodes) != 5 || nodes[0].NodeType != "clientNode" || nodes[0].SwitchPort != "8" || nodes[1].Name != "SW-CORE" {
		t.Fatalf("nodes = %+v", nodes)
	}
	if nodes[2].NodeType != "clientNode" || nodes[2].Name != "client" || nodes[2].SwitchPort != "8" ||
		nodes[3].NodeType != "deviceNode" || nodes[3].Name != "switch" || nodes[4].NodeType != "99" {
		t.Errorf("numeric node types: %+v", nodes[2:])
	}
}

func TestGetClientTopologyError(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, -1, "boom", "null")
	}))
	_, err := c.GetClientTopology(context.Background(), "s1", "aa:bb:cc:dd:ee:01")
	if err == nil || !strings.Contains(err.Error(), "getting client topology") {
		t.Errorf("error = %v, want wrapped fetch error", err)
	}
}

func TestTextOrIntegerRejectsInvalidTypes(t *testing.T) {
	for _, raw := range []string{"true", "1.5", "{}", "[]"} {
		var value textOrInteger
		if err := json.Unmarshal([]byte(raw), &value); err == nil {
			t.Errorf("accepted invalid scalar %s", raw)
		}
	}
}

func TestGetGatewayDHCPUsers(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/openapi/v1/abc123/sites/s1/gateways/aa-bb-cc-dd-ee-00/dhcp/user-list" {
			t.Errorf("path = %s", r.URL.Path)
		}
		if r.URL.Query().Get("pageSize") == "" {
			t.Error("pageSize is required")
		}
		writeEnvelope(w, 0, "", `{"totalRows":5,"data":[
			{"ipAddress":"10.0.10.20","macAddress":"aa-bb-cc-dd-ee-01","name":"pc1","netName":"Trusted","leftLeaseTime":3600},
			{"leftLeaseTime":"1800"},{"leftLeaseTime":"00:30:00"},{"leftLeaseTime":""},{"leftLeaseTime":null}
		]}`)
	}))
	rows, err := c.GetGatewayDHCPUsers(context.Background(), "s1", "aa:bb:cc:dd:ee:00")
	if err != nil {
		t.Fatalf("GetGatewayDHCPUsers: %v", err)
	}
	if len(rows) != 5 || rows[0].IP != "10.0.10.20" || NormalizeMAC(rows[0].MAC) != "aabbccddee01" || rows[0].NetworkName != "Trusted" {
		t.Fatalf("rows = %+v", rows)
	}
	if rows[0].LeftLeaseSec != 3600 || rows[1].LeftLeaseSec != 1800 || rows[2].LeftLeaseSec != 0 || rows[2].LeftLeaseTime != "00:30:00" {
		t.Errorf("incorrect lease seconds: %+v", rows)
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
