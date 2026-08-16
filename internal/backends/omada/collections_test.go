package omada

import (
	"context"
	"net/http"
	"strconv"
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

func TestGetNetworksLiveWireShape(t *testing.T) {
	// Fixture mirrors the live 6.2.14 payload: DHCP state is nested under
	// "dhcpSettings" and the SSID is reported as "origName". There is no
	// top-level "dhcpEnabled" or "ssid" field on the wire.
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, 0, "", `{"totalRows":2,"data":[
			{"id":"n1","name":"LAN(Default)","purpose":"interface","vlan":1,
				"gatewaySubnet":"10.0.0.254/24","isolation":false,
				"dhcpSettings":{"enable":true,"leasetime":120},"deviceMac":"aa:bb:cc:dd:ee:00",
				"origName":"LAN","primary":true},
			{"id":"n2","name":"Trusted","purpose":"interface","vlan":10,
				"gatewaySubnet":"10.0.0.1/24","isolation":true,
				"dhcpSettings":{"enable":false},"deviceMac":"aa:bb:cc:dd:ee:00",
				"origName":"Trusted"}
		]}`)
	}))
	nets, err := c.GetNetworks(context.Background(), "s1")
	if err != nil {
		t.Fatalf("GetNetworks: %v", err)
	}
	if len(nets) != 2 {
		t.Fatalf("networks = %d, want 2", len(nets))
	}
	nf, op := nets[0], nets[1]
	if !nf.DHCPEnabled || nf.SSID != "LAN" {
		t.Errorf("LAN = dhcp %v ssid %q, want dhcp on and SSID LAN", nf.DHCPEnabled, nf.SSID)
	}
	if op.DHCPEnabled || op.SSID != "Trusted" || !op.Isolated || op.VLANID != 10 {
		t.Errorf("Trusted = %+v, want dhcp off, SSID Trusted, isolated, vlan 10", op)
	}
	if nf.DeviceMac != "aa:bb:cc:dd:ee:00" || nf.CIDR() != "10.0.0.0/24" {
		t.Errorf("LAN deviceMac/cidr = %q/%q", nf.DeviceMac, nf.CIDR())
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

func TestGetACLRulesRequiresTypeQuery(t *testing.T) {
	var queries []string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/abc123/api/v2/sites/s1/setting/firewall/acls" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		queries = append(queries, r.URL.RawQuery)
		if r.URL.Query().Get("type") != "1" {
			writeEnvelope(w, -1, "General error.", "null")
			return
		}
		writeEnvelope(w, 0, "", `{"totalRows":2,"data":[
			{"id":"a1","name":"Deny IoT","status":true,"policy":0,"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1"]},
			{"id":"a2","name":"Allow Web","status":true,"policy":1,"sourceType":"network","sourceIds":["n1"],"destinationType":"network","destinationIds":["n2"]}
		]}`)
	}))
	rules, err := c.GetACLRules(context.Background(), "s1")
	if err != nil {
		t.Fatalf("GetACLRules: %v", err)
	}
	if len(rules) != 2 || rules[1].Policy != ACLPolicyPermit || rules[0].Type != ACLTypeSwitch {
		t.Errorf("rules = %+v, want two switch rules with permit on the second", rules)
	}
	if len(queries) == 0 || !strings.Contains(queries[0], "type=1") {
		t.Errorf("queries = %v, want type=1 on the switch ACL fetch", queries)
	}
}

func TestGetGatewayACLRulesAndDisableFlag(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/abc123/api/v2/sites/s1/setting/firewall/acls" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.URL.Query().Get("type") != "0" {
			writeEnvelope(w, -1, "General error.", "null")
			return
		}
		writeEnvelope(w, 0, "", `{"totalRows":0,"currentPage":1,"currentSize":10,"data":[],"aclDisable":true}`)
	}))
	list, err := c.FetchACLs(context.Background(), "s1", ACLTypeGateway)
	if err != nil {
		t.Fatalf("FetchACLs: %v", err)
	}
	if !list.ACLDisable || len(list.Rules) != 0 || list.Type != ACLTypeGateway {
		t.Errorf("list = %+v, want empty gateway list with aclDisable", list)
	}
	rules, err := c.GetGatewayACLRules(context.Background(), "s1")
	if err != nil {
		t.Fatalf("GetGatewayACLRules: %v", err)
	}
	if rules == nil {
		t.Error("rules = nil, want empty slice so JSON evidence is [] not null")
	}
}

func TestGetNetworksPaginatesAllPages(t *testing.T) {
	// pageSize is 200, so exercise >200 networks across two pages.
	var pages []string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pages = append(pages, r.URL.RawQuery)
		if r.URL.Query().Get("currentPage") == "1" {
			var rows []string
			for i := 0; i < 200; i++ {
				rows = append(rows, `{"id":"n`+strconv.Itoa(i)+`","name":"Net `+strconv.Itoa(i)+`"}`)
			}
			writeEnvelope(w, 0, "", `{"totalRows":250,"data":[`+strings.Join(rows, ",")+`]}`)
			return
		}
		var rows []string
		for i := 200; i < 250; i++ {
			rows = append(rows, `{"id":"n`+strconv.Itoa(i)+`","name":"Net `+strconv.Itoa(i)+`"}`)
		}
		writeEnvelope(w, 0, "", `{"totalRows":250,"data":[`+strings.Join(rows, ",")+`]}`)
	}))
	nets, err := c.GetNetworks(context.Background(), "s1")
	if err != nil {
		t.Fatalf("GetNetworks: %v", err)
	}
	if len(nets) != 250 || nets[249].ID != "n249" {
		t.Errorf("networks = %d items, want 250 with last id n249", len(nets))
	}
	if len(pages) != 2 || pages[1] != "currentPage=2&currentPageSize=200" {
		t.Errorf("pages = %v, want page 2 to be fetched", pages)
	}
}

func TestGetSitesPaginatesAllPages(t *testing.T) {
	var pages []string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pages = append(pages, r.URL.RawQuery)
		if r.URL.Query().Get("currentPage") == "1" {
			writeEnvelope(w, 0, "", `{"totalRows":3,"data":[{"id":"s1","name":"A"},{"id":"s2","name":"B"}]}`)
			return
		}
		writeEnvelope(w, 0, "", `{"totalRows":3,"data":[{"id":"s3","name":"C"}]}`)
	}))
	sites, err := c.GetSites(context.Background())
	if err != nil {
		t.Fatalf("GetSites: %v", err)
	}
	if len(sites) != 3 || sites[2].Name != "C" {
		t.Errorf("sites = %+v, want three sites", sites)
	}
	if len(pages) != 2 {
		t.Errorf("pages = %v, want 2 pages fetched", pages)
	}
}

func TestGetACLRulesPaginatesAllPages(t *testing.T) {
	var pages []string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pages = append(pages, r.URL.RawQuery)
		page := r.URL.Query().Get("currentPage")
		if page == "1" {
			writeEnvelope(w, 0, "", `{"totalRows":3,"data":[{"id":"a1"},{"id":"a2"}]}`)
			return
		}
		writeEnvelope(w, 0, "", `{"totalRows":3,"data":[{"id":"a3"}]}`)
	}))
	rules, err := c.GetACLRules(context.Background(), "s1")
	if err != nil {
		t.Fatalf("GetACLRules: %v", err)
	}
	if len(rules) != 3 || rules[2].ID != "a3" {
		t.Errorf("rules = %+v, want three rules", rules)
	}
}

func TestGetClientsPaginatesAllPages(t *testing.T) {
	var pages []string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pages = append(pages, r.URL.RawQuery)
		if r.URL.Query().Get("currentPage") == "1" {
			writeEnvelope(w, 0, "", `{"totalRows":2,"data":[{"mac":"aa:11"}]}`)
			return
		}
		writeEnvelope(w, 0, "", `{"totalRows":2,"data":[{"mac":"bb:22"}]}`)
	}))
	clients, err := c.GetClients(context.Background(), "s1")
	if err != nil {
		t.Fatalf("GetClients: %v", err)
	}
	if len(clients) != 2 || clients[1].MAC != "bb:22" {
		t.Errorf("clients = %+v, want two clients", clients)
	}
	if len(pages) != 2 || pages[0] != "currentPage=1&currentPageSize=200&filters.active=true" {
		t.Errorf("pages = %v, want active-client filter on every page", pages)
	}
}

func TestGetGatewayACLRulesFetchError(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, -1101, "nope", "null")
	}))
	_, err := c.GetGatewayACLRules(context.Background(), "s1")
	if err == nil || !strings.Contains(err.Error(), "fetching ACL rules (type 0)") {
		t.Errorf("error = %v, want typed gateway fetch error", err)
	}
}

func TestGetACLRulesFetchError(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, -1101, "nope", "null")
	}))
	_, err := c.GetACLRules(context.Background(), "s1")
	if err == nil || !strings.Contains(err.Error(), "fetching ACL rules (type 1)") {
		t.Errorf("error = %v, want typed fetch error", err)
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

func TestFetchPaged_RepeatedPageDetected(t *testing.T) {
	// A controller that reports totalRows: 0 and ignores currentPage repeats
	// page 1 forever. fetchPaged must fail fast instead of looping.
	requested := 0
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested++
		writeEnvelope(w, 0, "", `{"totalRows":0,"data":[{"mac":"aa:11"}]}`)
	}))
	_, _, err := fetchPaged[struct{ MAC string }](context.Background(), c, "sites/s1/clients", defaultPageSize)
	if err == nil || !strings.Contains(err.Error(), "repeated page 1") {
		t.Fatalf("error = %v, want repeated-page-1 error", err)
	}
	if requested != 2 {
		t.Errorf("requests = %d, want 2 (page 1 then repeat detected)", requested)
	}
}

func TestFetchPaged_PageCap(t *testing.T) {
	// A controller with totalRows: 0 that returns a distinct non-empty page
	// for every request would never terminate on its own — the page cap must
	// stop it.
	requested := 0
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested++
		writeEnvelope(w, 0, "", `{"totalRows":0,"data":[{"mac":"aa:`+strconv.Itoa(requested)+`"}]}`)
	}))
	_, _, err := fetchPaged[struct{ MAC string }](context.Background(), c, "sites/s1/clients", defaultPageSize)
	if err == nil || !strings.Contains(err.Error(), "did not terminate after "+strconv.Itoa(maxPages)+" pages") {
		t.Fatalf("error = %v, want page-cap error", err)
	}
	if requested != maxPages {
		t.Errorf("requests = %d, want %d (cap aborts before the next page)", requested, maxPages)
	}
}
