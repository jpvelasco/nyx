package omada

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// BDD S3.3 — single lan-networks endpoint, DHCP state nested under
// "dhcpSettingsVO". There is no "dhcpEnabled" or "ssid" field on the wire;
// deviceMac/origName are optional and decode to zero values when absent.
func TestGetNetworksLiveWireShape(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/openapi/v1/abc123/sites/s1/lan-networks" {
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeEnvelope(w, 0, "", `{"totalRows":2,"data":[
			{"id":"n1","name":"LAN(Default)","purpose":"interface","vlan":1,
				"gatewaySubnet":"10.0.0.254/24","isolation":false,
				"dhcpSettingsVO":{"enable":true,"leasetime":120},"deviceMac":"aa:bb:cc:dd:ee:00"},
			{"id":"n2","name":"Trusted","purpose":"interface","vlan":10,
				"gatewaySubnet":"10.0.0.1/24","isolation":true,
				"dhcpSettingsVO":{"enable":false}}
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
	if !nf.DHCPEnabled {
		t.Errorf("LAN dhcp = %v, want on (dhcpSettingsVO.enable)", nf.DHCPEnabled)
	}
	if op.DHCPEnabled || !op.Isolated || op.VLANID != 10 {
		t.Errorf("Trusted = %+v, want dhcp off, isolated, vlan 10", op)
	}
	if nf.DeviceMac != "aa:bb:cc:dd:ee:00" || nf.CIDR() != "10.0.0.0/24" {
		t.Errorf("LAN deviceMac/cidr = %q/%q", nf.DeviceMac, nf.CIDR())
	}
	// deviceMac/origName absent on the second row must decode to zero values.
	if op.DeviceMac != "" {
		t.Errorf("Trusted deviceMac = %q, want empty when absent", op.DeviceMac)
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

func TestGetNetworksFetchError(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	_, err := c.GetNetworks(context.Background(), "s1")
	if err == nil || !strings.Contains(err.Error(), "could not fetch networks") {
		t.Errorf("error = %v, want could-not-fetch-networks", err)
	}
}

// BDD S3.7 — ACL reads are per-scope paths (acls/osw-acls, acls/osg-acls):
// no "type" query, the rule name rides on "description" (1-512 chars).
func TestGetACLRulesUsesSwitchScopePath(t *testing.T) {
	var queries []string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/openapi/v1/abc123/sites/s1/acls/osw-acls" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		queries = append(queries, r.URL.RawQuery)
		if r.URL.Query().Get("page") == "" {
			writeEnvelope(w, -1001, "bad params", "null")
			return
		}
		writeEnvelope(w, 0, "", `{"totalRows":2,"data":[
			{"id":"a1","description":"Deny IoT","status":true,"policy":0,"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1"]},
			{"id":"a2","description":"Allow Web","status":true,"policy":1,"sourceType":"network","sourceIds":["n1"],"destinationType":"network","destinationIds":["n2"]}
		]}`)
	}))
	rules, err := c.GetACLRules(context.Background(), "s1")
	if err != nil {
		t.Fatalf("GetACLRules: %v", err)
	}
	if len(rules) != 2 || rules[1].Policy != ACLPolicyPermit || rules[0].Type != ACLTypeSwitch {
		t.Errorf("rules = %+v, want two switch rules with permit on the second", rules)
	}
	if rules[0].Name != "Deny IoT" || rules[1].Name != "Allow Web" {
		t.Errorf("rule names = %q/%q, want descriptions from the wire", rules[0].Name, rules[1].Name)
	}
	if len(queries) == 0 || !strings.Contains(queries[0], "page=1") || strings.Contains(queries[0], "type=") {
		t.Errorf("queries = %v, want page params and no type query", queries)
	}
}

// BDD S3.7 — the list envelope carries no capability flags: a scope list is
// just the scope type and its rules.
func TestGetGatewayACLRulesNoCapabilityFlags(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/openapi/v1/abc123/sites/s1/acls/osg-acls" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeEnvelope(w, 0, "", `{"totalRows":0,"currentPage":1,"currentSize":10,"data":[]}`)
	}))
	list, err := c.FetchACLs(context.Background(), "s1", ACLTypeGateway)
	if err != nil {
		t.Fatalf("FetchACLs: %v", err)
	}
	if list.Type != ACLTypeGateway {
		t.Errorf("list = %+v, want gateway type", list)
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
		if r.URL.Query().Get("page") == "1" {
			var rows []string
			for i := 0; i < 200; i++ {
				rows = append(rows, `{"id":"n`+strconv.Itoa(i)+`","name":"Net `+strconv.Itoa(i)+`"}`)
			}
			writeEnvelope(w, 0, "", `{"totalRows":250,"currentPage":1,"currentSize":200,"data":[`+strings.Join(rows, ",")+`]}`)
			return
		}
		var rows []string
		for i := 200; i < 250; i++ {
			rows = append(rows, `{"id":"n`+strconv.Itoa(i)+`","name":"Net `+strconv.Itoa(i)+`"}`)
		}
		writeEnvelope(w, 0, "", `{"totalRows":250,"currentPage":2,"currentSize":50,"data":[`+strings.Join(rows, ",")+`]}`)
	}))
	nets, err := c.GetNetworks(context.Background(), "s1")
	if err != nil {
		t.Fatalf("GetNetworks: %v", err)
	}
	if len(nets) != 250 || nets[249].ID != "n249" {
		t.Errorf("networks = %d items, want 250 with last id n249", len(nets))
	}
	if len(pages) != 2 || pages[1] != "page=2&pageSize=200" {
		t.Errorf("pages = %v, want page 2 to be fetched", pages)
	}
}

func TestGetSitesPaginatesAllPages(t *testing.T) {
	var pages []string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pages = append(pages, r.URL.RawQuery)
		if r.URL.Query().Get("page") == "1" {
			writeEnvelope(w, 0, "", `{"totalRows":3,"currentPage":1,"currentSize":2,"data":[{"siteId":"s1","name":"A"},{"siteId":"s2","name":"B"}]}`)
			return
		}
		writeEnvelope(w, 0, "", `{"totalRows":3,"currentPage":2,"currentSize":1,"data":[{"siteId":"s3","name":"C"}]}`)
	}))
	sites, err := c.GetSites(context.Background())
	if err != nil {
		t.Fatalf("GetSites: %v", err)
	}
	if len(sites) != 3 || sites[2].Name != "C" {
		t.Errorf("sites = %+v, want three sites", sites)
	}
	if len(pages) != 2 || pages[0] != "page=1&pageSize=200" {
		t.Errorf("pages = %v, want 2 pages fetched with page/pageSize params", pages)
	}
}

func TestGetACLRulesPaginatesAllPages(t *testing.T) {
	var pages []string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/openapi/v1/abc123/sites/s1/acls/osw-acls" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		pages = append(pages, r.URL.RawQuery)
		page := r.URL.Query().Get("page")
		if page == "1" {
			writeEnvelope(w, 0, "", `{"totalRows":3,"data":[{"id":"a1","description":"one"},{"id":"a2","description":"two"}]}`)
			return
		}
		writeEnvelope(w, 0, "", `{"totalRows":3,"data":[{"id":"a3","description":"three"}]}`)
	}))
	rules, err := c.GetACLRules(context.Background(), "s1")
	if err != nil {
		t.Fatalf("GetACLRules: %v", err)
	}
	if len(rules) != 3 || rules[2].ID != "a3" {
		t.Errorf("rules = %+v, want three rules", rules)
	}
	if len(pages) != 2 || pages[0] != "page=1&pageSize=200" {
		t.Errorf("pages = %v, want page/pageSize params", pages)
	}
}

// BDD S3.4 — the client endpoint is sites/{id}/networks/client, thin rows
// {mac,name,type}, and it takes no filter query.
func TestGetClientsPaginatesAllPages(t *testing.T) {
	var pages []string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/openapi/v1/abc123/sites/s1/networks/client" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		pages = append(pages, r.URL.RawQuery)
		if r.URL.Query().Get("page") == "1" {
			writeEnvelope(w, 0, "", `{"totalRows":2,"data":[{"mac":"aa:11","name":"one","type":"wired"}]}`)
			return
		}
		writeEnvelope(w, 0, "", `{"totalRows":2,"data":[{"mac":"bb:22","name":"two","type":"wired"}]}`)
	}))
	clients, err := c.GetClients(context.Background(), "s1")
	if err != nil {
		t.Fatalf("GetClients: %v", err)
	}
	if len(clients) != 2 || clients[1].MAC != "bb:22" {
		t.Errorf("clients = %+v, want two clients", clients)
	}
	if len(pages) != 2 || pages[0] != "page=1&pageSize=200" {
		t.Errorf("pages = %v, want page/pageSize only (no filter query)", pages)
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

// BDD S3.4 — thin rows: the wire carries only mac, name, and type.
func TestGetClients(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, 0, "", `{"totalRows":1,"data":[
			{"mac":"11:22:33:44:55:66","name":"PC-01","type":"wired"}
		]}`)
	}))
	clients, err := c.GetClients(context.Background(), "s1")
	if err != nil {
		t.Fatalf("GetClients: %v", err)
	}
	if len(clients) != 1 || clients[0].MAC != "11:22:33:44:55:66" {
		t.Errorf("clients = %+v, want one client", clients)
	}
	if clients[0].Name != "PC-01" || clients[0].Type != "wired" {
		t.Errorf("client = %+v, want name/type from the thin row", clients[0])
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
	// A controller that reports totalRows: 0 and ignores the page param
	// repeats page 1 forever. fetchPaged must fail fast instead of looping.
	requested := 0
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested++
		writeEnvelope(w, 0, "", `{"totalRows":0,"data":[{"mac":"aa:11"}]}`)
	}))
	_, _, err := fetchPaged[struct{ MAC string }](context.Background(), c, "sites/s1/networks/client", defaultPageSize)
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
	_, _, err := fetchPaged[struct{ MAC string }](context.Background(), c, "sites/s1/networks/client", defaultPageSize)
	if err == nil || !strings.Contains(err.Error(), "did not terminate after "+strconv.Itoa(maxPages)+" pages") {
		t.Fatalf("error = %v, want page-cap error", err)
	}
	if requested != maxPages {
		t.Errorf("requests = %d, want %d (cap aborts before the next page)", requested, maxPages)
	}
}
