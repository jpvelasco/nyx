package omada

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestGetNetworksEndpointFallback(t *testing.T) {
	// First candidate path 404s; second path returns paged data.
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/abc123/api/v2/sites/s1/setting/lan/networks":
			w.WriteHeader(http.StatusNotFound)
		case "/abc123/api/v2/sites/s1/setting/networks":
			writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"n1","name":"LAN","gatewaySubnet":"10.0.0.1/24"}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	nets, err := c.GetNetworks(context.Background(), "s1")
	if err != nil {
		t.Fatalf("GetNetworks: %v", err)
	}
	if len(nets) != 1 || nets[0].Name != "LAN" {
		t.Errorf("networks = %+v, want one LAN network", nets)
	}
}

func TestGetNetworksResponseShapes(t *testing.T) {
	t.Run("direct array", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeEnvelope(w, 0, "", `[{"id":"n1","name":"LAN","gatewaySubnet":"10.0.0.1/24"}]`)
		}))
		nets, err := c.GetNetworks(context.Background(), "s1")
		if err != nil {
			t.Fatalf("GetNetworks: %v", err)
		}
		if len(nets) != 1 || nets[0].Name != "LAN" {
			t.Errorf("networks = %+v, want one LAN network", nets)
		}
	})

	t.Run("get error", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		_, err := c.GetSites(context.Background())
		if err == nil || !strings.Contains(err.Error(), "getting sites") {
			t.Errorf("error = %v, want getting-sites wrapper", err)
		}
	})
}

func TestGetNetworksParseFailThenSucceed(t *testing.T) {
	// First candidate returns an unparseable payload (get succeeds), so we
	// must continue to the next endpoint.
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/abc123/api/v2/sites/s1/setting/lan/networks":
			writeEnvelope(w, 0, "", `"not-network-shaped"`)
		case "/abc123/api/v2/sites/s1/setting/networks":
			writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"n1","name":"LAN"}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	nets, err := c.GetNetworks(context.Background(), "s1")
	if err != nil {
		t.Fatalf("GetNetworks: %v", err)
	}
	if len(nets) != 1 || nets[0].Name != "LAN" {
		t.Errorf("networks = %+v, want one LAN network", nets)
	}
}

func TestGetNetworksAllPathsFail(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	_, err := c.GetNetworks(context.Background(), "s1")
	if err == nil || !strings.Contains(err.Error(), "could not fetch networks") {
		t.Errorf("error = %v, want could-not-fetch-networks", err)
	}
}

func TestGetACLRulesEndpointFallback(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/abc123/api/v2/sites/s1/setting/firewall/acl":
			w.WriteHeader(http.StatusNotFound)
		case "/abc123/api/v2/sites/s1/setting/firewall/acls":
			writeEnvelope(w, 0, "", `{"totalRows":2,"data":[
				{"id":"a1","name":"Deny IoT","status":true,"policy":"drop"},
				{"id":"a2","name":"Allow Web","status":true,"policy":"accept"}
			]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	rules, err := c.GetACLRules(context.Background(), "s1")
	if err != nil {
		t.Fatalf("GetACLRules: %v", err)
	}
	if len(rules) != 2 || rules[1].Policy != "accept" {
		t.Errorf("rules = %+v, want two rules", rules)
	}
}

func TestGetGatewayACLRulesDirectArray(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/abc123/api/v2/sites/s1/setting/firewall/gwacl":
			w.WriteHeader(http.StatusNotFound)
		case "/abc123/api/v2/sites/s1/setting/firewall/gwacls":
			writeEnvelope(w, 0, "", `[{"id":"g1","name":"WAN block","status":false,"policy":"drop"}]`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	rules, err := c.GetGatewayACLRules(context.Background(), "s1")
	if err != nil {
		t.Fatalf("GetGatewayACLRules: %v", err)
	}
	if len(rules) != 1 || rules[0].ID != "g1" {
		t.Errorf("rules = %+v, want one g1 rule", rules)
	}
}

func TestTryACLPathsAllFail(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, -1101, "nope", "null")
	}))
	_, err := c.GetACLRules(context.Background(), "s1")
	if err == nil || !strings.Contains(err.Error(), "no ACL endpoint responded") {
		t.Errorf("error = %v, want no-ACL-endpoint error", err)
	}
}

func TestGetClients(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, 0, "", `{"totalRows":1,"data":[
			{"mac":"11:22:33:44:55:66","ip":"10.0.0.7","networkName":"Trusted","active":true}
		]}`)
	}))
	clients, err := c.GetClients(context.Background(), "s1")
	if err != nil {
		t.Fatalf("GetClients: %v", err)
	}
	if len(clients) != 1 || clients[0].MAC != "11:22:33:44:55:66" {
		t.Errorf("clients = %+v, want one active client", clients)
	}
}

func TestGetClientsEmpty(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
	}))
	clients, err := c.GetClients(context.Background(), "s1")
	if err != nil {
		t.Fatalf("GetClients: %v", err)
	}
	if len(clients) != 0 {
		t.Errorf("clients = %+v, want none", clients)
	}
}

func TestGetClientsError(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, -1000, "expired", "null")
	}))
	_, err := c.GetClients(context.Background(), "s1")
	if err == nil || !strings.Contains(err.Error(), "getting clients") {
		t.Errorf("error = %v, want getting-clients wrapper", err)
	}
}
