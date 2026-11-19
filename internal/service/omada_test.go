package service

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
	"github.com/jpvelasco/nyx/internal/testutil"
)

const omadaTestInfo = `{"errorCode":0,"msg":"","result":{"controllerVer":"6.4.5.1","apiVer":"2.0","omadacId":"abc123","configured":true,"omadacCategory":"advanced"}}`

// omadaTestServer spins up a TLS test server that answers /api/info like a
// real Omada controller; everything else is delegated to h.
func omadaTestServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/info" {
			testutil.WriteBody(w, omadaTestInfo)
			return
		}
		h(w, r)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func writeOmadaEnvelope(w io.Writer, errorCode int, result string) {
	testutil.WriteBody(w, `{"errorCode":`+strconv.Itoa(errorCode)+`,"msg":"","result":`+result+`}`)
}

func TestOmadaServiceInventory(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/openapi/v1/abc123/sites/s1/lan-networks":
			writeOmadaEnvelope(w, 0, `{"totalRows":2,"data":[
				{"id":"n1","name":"Trusted","purpose":"lan","vlan":10,"gatewaySubnet":"10.0.10.1/24","deviceMac":"aa:bb:cc:dd:ee:00","dhcpSettingsVO":{"enable":true}},
				{"id":"n2","name":"IoT","purpose":"lan","vlan":20,"gatewaySubnet":"10.0.20.1/24","deviceMac":"aa:bb:cc:dd:ee:00","dhcpSettingsVO":{"enable":false}}]}`)
		case "/openapi/v1/abc123/sites/s1/networks/devices":
			writeOmadaEnvelope(w, 0, `[
				{"id":"d1","name":"GW-CORE","model":"GW-CORE","type":"gateway","mac":"aa:bb:cc:dd:ee:00","ip":"10.0.0.254","firmwareVersion":"2.2.3","needUpgrade":true},
				{"id":"d2","name":"SW-2428P","model":"SW-2428P","type":"switch","mac":"aa:bb:cc:dd:ee:01","ip":"10.0.0.253"}]`)
		case "/openapi/v1/abc123/sites/s1/acls/osg-acls":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"g1","description":"Trusted Deny","status":true,"policy":0}]}`)
		case "/openapi/v1/abc123/sites/s1/acls/osw-acls":
			writeOmadaEnvelope(w, 0, `{"totalRows":0,"data":[]}`)
		case "/openapi/v1/abc123/sites/s1/networks/client":
			writeOmadaEnvelope(w, 0, `{"totalRows":2,"data":[{"mac":"aa","name":"PC-01","type":"wired"},{"mac":"bb","name":"PC-02","type":"wired"}]}`)
		case "/openapi/v1/abc123/sites/s1/setting/service/dhcp/user-list":
			writeOmadaEnvelope(w, 0, `{"totalRows":0,"data":[]}`)
		case "/openapi/v1/abc123/sites/s1/setting/service/mdns":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"m1","name":"media","status":true,"type":1,"profileIds":["p1"],"osg":{"serviceNetworks":["n2"],"clientNetworks":["n1"]}}]}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	inv, err := NewOmadaService().Inventory(context.Background(), OmadaOptions{Host: ts.URL, SkipTLSVerify: true})
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	if inv.Site != "HQ" || inv.ClientCount != 2 || inv.ControllerVersion != "6.4.5.1" {
		t.Errorf("summary = %s/%d/%s, want HQ/2/6.4.5.1", inv.Site, inv.ClientCount, inv.ControllerVersion)
	}
	if inv.ControllerCategory != "advanced" {
		t.Errorf("controller_category = %q, want advanced", inv.ControllerCategory)
	}
	if len(inv.Devices) != 2 || inv.Devices[0].Name != "GW-CORE" || inv.Devices[0].Type != "gateway" {
		t.Errorf("devices = %+v, want gateway first (sorted)", inv.Devices)
	}
	if len(inv.Devices[0].Networks) != 2 || inv.Devices[0].Networks[0] != "trusted" {
		t.Errorf("gateway networks = %v, want [trusted iot] via deviceMac binding", inv.Devices[0].Networks)
	}
	if inv.NetworkGateways["trusted"] != "GW-CORE" || inv.NetworkGateways["iot"] != "GW-CORE" {
		t.Errorf("network_gateways = %v", inv.NetworkGateways)
	}
	if len(inv.ACLScopes) != 2 {
		t.Fatalf("acl_scopes = %+v, want 2", inv.ACLScopes)
	}
	gw, sw := inv.ACLScopes[0], inv.ACLScopes[1]
	if gw.Scope != "gateway" || gw.RuleCount != 1 {
		t.Errorf("gateway scope = %+v, want 1 rule", gw)
	}
	if sw.Scope != "switch" || sw.RuleCount != 0 {
		t.Errorf("switch scope = %+v, want 0 rules", sw)
	}
	if inv.MDNS == nil || inv.MDNS.Status != "available" || len(inv.MDNS.Rules) != 1 || inv.MDNS.Rules[0].Name != "media" {
		t.Errorf("mDNS = %+v, want one available media rule", inv.MDNS)
	}
	if len(inv.Warnings) != 0 {
		t.Errorf("warnings = %v, want none", inv.Warnings)
	}
}

func TestOmadaServiceInventoryErrors(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, -44106, `null`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	_, err := NewOmadaService().Inventory(context.Background(), OmadaOptions{Host: ts.URL, ClientID: "a", ClientSecret: "b", SkipTLSVerify: true})
	if err == nil {
		t.Error("expected token mint failure to propagate")
	}
}

func TestOmadaServiceInfo(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected authenticated request: %s %s", r.Method, r.URL.Path)
	})
	info, err := NewOmadaService().Info(context.Background(), OmadaOptions{Host: ts.URL, SkipTLSVerify: true})
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if info.Provider != "omada" {
		t.Errorf("provider = %q, want omada", info.Provider)
	}
	if info.Version != "6.4.5.1" {
		t.Errorf("version = %q, want 6.4.5.1", info.Version)
	}
	if info.APIVersion != "2.0" {
		t.Errorf("api_version = %q, want 2.0", info.APIVersion)
	}
	if info.OmadaCID != "abc123" {
		t.Errorf("omada_cid = %q, want abc123", info.OmadaCID)
	}
	if !info.Configured {
		t.Error("configured = false, want true")
	}
}

func TestOmadaServiceInfoError(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeOmadaEnvelope(w, 57, "null")
	}))
	t.Cleanup(ts.Close)

	_, err := NewOmadaService().Info(context.Background(), OmadaOptions{Host: ts.URL, SkipTLSVerify: true})
	if err == nil || !strings.Contains(err.Error(), "controller returned error 57") {
		t.Fatalf("Info error = %v, want controller error 57", err)
	}
}

func TestOmadaServiceListNetworks(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			if r.Method != http.MethodPost {
				t.Errorf("login method = %s, want POST", r.Method)
			}
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/openapi/v1/abc123/sites/s1/lan-networks":
			// Open API shape: DHCP flag nested under dhcpSettingsVO
			writeOmadaEnvelope(w, 0, `{"totalRows":2,"data":[
				{"id":"n1","name":"Trusted","purpose":"lan","vlan":10,"gatewaySubnet":"10.0.10.1/24","isolation":false,"dhcpGuard":true,"dhcpSettingsVO":{"enable":true,"ipaddrStart":"10.0.10.20","ipaddrEnd":"10.0.10.200","leasetime":120},"deviceMac":"aa:bb:cc:dd:ee:00"},
				{"id":"n2","name":"IoT","purpose":"lan","vlan":20,"gatewaySubnet":"10.0.20.1/24","isolation":true,"dhcpSettingsVO":{"enable":false},"deviceMac":"aa:bb:cc:dd:ee:00"}]}`)
		default:
			http.NotFound(w, r)
		}
	})

	nets, err := NewOmadaService().ListNetworks(context.Background(), OmadaOptions{
		Host: ts.URL, ClientID: "admin", ClientSecret: "pw", SkipTLSVerify: true,
	})
	if err != nil {
		t.Fatalf("ListNetworks: %v", err)
	}
	if len(nets) != 2 {
		t.Fatalf("got %d networks, want 2", len(nets))
	}
	trusted := nets[0]
	if trusted.Name != "Trusted" || trusted.CIDR != "10.0.10.0/24" || trusted.Gateway != "10.0.10.1" {
		t.Errorf("trusted = %+v, want name/cidr/gateway derived from gatewaySubnet", trusted)
	}
	if trusted.VLANID != 10 || !trusted.DHCPEnabled || trusted.Isolated {
		t.Errorf("trusted = %+v, want vlan 10, dhcp on, not isolated", trusted)
	}
	if trusted.DHCPStart != "10.0.10.20" || trusted.DHCPEnd != "10.0.10.200" || !trusted.DHCPGuard {
		t.Errorf("trusted pool/posture = %+v", trusted)
	}
	iot := nets[1]
	if iot.VLANID != 20 || iot.DHCPEnabled || !iot.Isolated {
		t.Errorf("iot = %+v, want vlan 20, dhcp off, isolated", iot)
	}
}

func TestOmadaServiceListAPChannels_EmptySite(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"siteId":"s1","name":"HQ"}]}`)
		case "/openapi/v1/abc123/sites/s1/networks/devices":
			writeOmadaEnvelope(w, 0, `[{"type":"gateway","name":"gateway"}]`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			http.NotFound(w, r)
		}
	})
	rows, err := NewOmadaService().ListAPChannels(context.Background(), OmadaOptions{
		Host: ts.URL, ClientID: "admin", ClientSecret: "pw", SkipTLSVerify: true,
	})
	if err != nil || rows == nil || len(rows) != 0 {
		t.Fatalf("rows = %v, error = %v; want empty inventory", rows, err)
	}
}

func TestOmadaServiceListGatewayDHCPUsers(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/openapi/v1/abc123/sites/s1/gateways/aa-bb-cc-dd-ee-00/dhcp/user-list":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[
				{"ipAddress":"10.0.10.20","macAddress":"aa-bb-cc-dd-ee-01","name":"pc1","netName":"Trusted","leftLeaseTime":3600}]}`)
		default:
			http.NotFound(w, r)
		}
	})
	rows, err := NewOmadaService().ListGatewayDHCPUsers(context.Background(), OmadaOptions{
		Host: ts.URL, ClientID: "admin", ClientSecret: "pw", SkipTLSVerify: true,
	}, "aa:bb:cc:dd:ee:00")
	if err != nil {
		t.Fatalf("ListGatewayDHCPUsers: %v", err)
	}
	if len(rows) != 1 || rows[0].IP != "10.0.10.20" || rows[0].NetworkName != "Trusted" {
		t.Fatalf("rows = %+v", rows)
	}
	if _, err := NewOmadaService().ListGatewayDHCPUsers(context.Background(), OmadaOptions{
		Host: ts.URL, ClientID: "admin", ClientSecret: "pw", SkipTLSVerify: true,
	}, ""); err == nil {
		t.Fatal("empty gateway_mac must error")
	}
}

func TestOmadaServiceDHCPExtras(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/openapi/v1/abc123/sites/s1/networks/n1/dhcp-server-info":
			writeOmadaEnvelope(w, 0, `{"availableIpCount":12,"totalIpCount":180,"ipaddrStart":"10.0.10.20","ipaddrEnd":"10.0.10.200"}`)
		case "/openapi/v1/abc123/sites/s1/dhcpSnoops/status":
			writeOmadaEnvelope(w, 0, `{"enable":true}`)
		case "/openapi/v1/abc123/sites/s1/dhcpSnoops":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"r1","name":"trust","enabled":true}]}`)
		case "/openapi/v1/abc123/sites/s1/lan-multicasts":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"m1","name":"ssdp","status":true}]}`)
		default:
			http.NotFound(w, r)
		}
	})
	opts := OmadaOptions{Host: ts.URL, ClientID: "a", ClientSecret: "b", SkipTLSVerify: true}
	info, err := NewOmadaService().GetDHCPServerInfo(context.Background(), opts, "n1")
	if err != nil || info.AvailableIPs != 12 {
		t.Fatalf("info = %+v err=%v", info, err)
	}
	if _, err := NewOmadaService().GetDHCPServerInfo(context.Background(), opts, ""); err == nil {
		t.Fatal("empty network_id must error")
	}
	st, err := NewOmadaService().GetDHCPSnoopStatus(context.Background(), opts)
	if err != nil || !st.Enabled {
		t.Fatalf("status = %+v err=%v", st, err)
	}
	rules, err := NewOmadaService().ListDHCPSnoops(context.Background(), opts)
	if err != nil || len(rules) != 1 {
		t.Fatalf("rules = %+v err=%v", rules, err)
	}
	mcs, err := NewOmadaService().ListLANMulticasts(context.Background(), opts)
	if err != nil || len(mcs) != 1 || !mcs[0].Enabled {
		t.Fatalf("multicasts = %+v err=%v", mcs, err)
	}
}

func TestOmadaServiceDHCPExtras_Errors(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		default:
			writeOmadaEnvelope(w, -1, "null")
		}
	})
	opts := OmadaOptions{Host: ts.URL, ClientID: "a", ClientSecret: "b", SkipTLSVerify: true}
	if _, err := NewOmadaService().GetDHCPServerInfo(context.Background(), opts, "n1"); err == nil {
		t.Fatal("expected server-info fetch error")
	}
	if _, err := NewOmadaService().GetDHCPSnoopStatus(context.Background(), opts); err == nil {
		t.Fatal("expected snoop-status fetch error")
	}
	if _, err := NewOmadaService().ListDHCPSnoops(context.Background(), opts); err == nil {
		t.Fatal("expected snoop-rules fetch error")
	}
	if _, err := NewOmadaService().ListLANMulticasts(context.Background(), opts); err == nil {
		t.Fatal("expected multicast fetch error")
	}
}

func TestOmadaServiceGetClientTopology(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case r.URL.Path == "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case r.Method == http.MethodPost && r.URL.Path == "/openapi/v1/abc123/sites/s1/clients/aa-bb-cc-dd-ee-01/client-link-topology":
			writeOmadaEnvelope(w, 0, `[{"nodeType":"clientNode","clientNode":{"mac":"aa-bb-cc-dd-ee-01","upOswInfo":{"port":"8"}}}]`)
		default:
			http.NotFound(w, r)
		}
	})
	nodes, err := NewOmadaService().GetClientTopology(context.Background(), OmadaOptions{
		Host: ts.URL, ClientID: "admin", ClientSecret: "pw", SkipTLSVerify: true,
	}, "aa:bb:cc:dd:ee:01")
	if err != nil {
		t.Fatalf("GetClientTopology: %v", err)
	}
	if len(nodes) != 1 || nodes[0].SwitchPort != "8" {
		t.Fatalf("nodes = %+v", nodes)
	}
	if _, err := NewOmadaService().GetClientTopology(context.Background(), OmadaOptions{
		Host: ts.URL, ClientID: "admin", ClientSecret: "pw", SkipTLSVerify: true,
	}, ""); err == nil {
		t.Fatal("empty client_mac must error")
	}
}

func TestOmadaServiceGetClientTopology_Errors(t *testing.T) {
	if _, err := NewOmadaService().GetClientTopology(context.Background(), OmadaOptions{
		Host: "https://127.0.0.1:1", ClientID: "admin", ClientSecret: "pw", SkipTLSVerify: true,
	}, "aa:bb:cc:dd:ee:01"); err == nil {
		t.Fatal("unreachable host must error")
	}
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		default:
			writeOmadaEnvelope(w, -1, "null")
		}
	})
	_, err := NewOmadaService().GetClientTopology(context.Background(), OmadaOptions{
		Host: ts.URL, ClientID: "admin", ClientSecret: "pw", SkipTLSVerify: true,
	}, "aa:bb:cc:dd:ee:01")
	if err == nil || !strings.Contains(err.Error(), "fetching client topology") {
		t.Fatalf("err = %v, want fetching-client-topology wrap", err)
	}
}

func TestOmadaServiceListNetworks_SiteSelection(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":2,"data":[
				{"id":"s1","name":"HQ"},
				{"id":"s2","name":"Branch"}]}`)
		case "/openapi/v1/abc123/sites/s1/lan-networks":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"n-hq","name":"HQ Net"}]}`)
		case "/openapi/v1/abc123/sites/s2/lan-networks":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"n-branch","name":"Branch Net"}]}`)
		default:
			http.NotFound(w, r)
		}
	})

	t.Run("defaults to first site", func(t *testing.T) {
		nets, err := NewOmadaService().ListNetworks(context.Background(), OmadaOptions{
			Host: ts.URL, ClientID: "admin", ClientSecret: "pw", SkipTLSVerify: true,
		})
		if err != nil {
			t.Fatalf("ListNetworks: %v", err)
		}
		if len(nets) != 1 || nets[0].Name != "HQ Net" {
			t.Errorf("nets = %+v, want HQ Net from first site", nets)
		}
	})

	t.Run("selects named site", func(t *testing.T) {
		nets, err := NewOmadaService().ListNetworks(context.Background(), OmadaOptions{
			Host: ts.URL, ClientID: "admin", ClientSecret: "pw", Site: "Branch", SkipTLSVerify: true,
		})
		if err != nil {
			t.Fatalf("ListNetworks: %v", err)
		}
		if len(nets) != 1 || nets[0].Name != "Branch Net" {
			t.Errorf("nets = %+v, want Branch Net from named site", nets)
		}
	})

	t.Run("unknown site errors with available sites", func(t *testing.T) {
		_, err := NewOmadaService().ListNetworks(context.Background(), OmadaOptions{
			Host: ts.URL, ClientID: "admin", ClientSecret: "pw", Site: "Nope", SkipTLSVerify: true,
		})
		if err == nil || !strings.Contains(err.Error(), "not found; available sites: HQ, Branch") {
			t.Fatalf("ListNetworks error = %v, want site not found listing sites", err)
		}
	})
}

func TestOmadaService_SessionFailures(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, -44106, "bad creds")
		default:
			http.NotFound(w, r)
		}
	})
	authOpts := OmadaOptions{Host: ts.URL, ClientID: "admin", ClientSecret: "nope", SkipTLSVerify: true}
	connectOpts := OmadaOptions{Host: "https://127.0.0.1:1", ClientID: "admin", ClientSecret: "pw", SkipTLSVerify: true}
	cases := []struct {
		name string
		opts OmadaOptions
		want string
		call func(opts OmadaOptions) error
	}{
		{"networks/login-fail", authOpts, "token mint failed", func(opts OmadaOptions) error {
			_, err := NewOmadaService().ListNetworks(context.Background(), opts)
			return err
		}},
		{"acls/login-fail", authOpts, "token mint failed", func(opts OmadaOptions) error {
			_, err := NewOmadaService().ListACLs(context.Background(), opts)
			return err
		}},
		{"clients/login-fail", authOpts, "token mint failed", func(opts OmadaOptions) error {
			_, err := NewOmadaService().ListClients(context.Background(), opts)
			return err
		}},
		{"networks/connect-fail", connectOpts, "fetching controller info", func(opts OmadaOptions) error {
			_, err := NewOmadaService().ListNetworks(context.Background(), opts)
			return err
		}},
		{"acls/connect-fail", connectOpts, "fetching controller info", func(opts OmadaOptions) error {
			_, err := NewOmadaService().ListACLs(context.Background(), opts)
			return err
		}},
		{"clients/connect-fail", connectOpts, "fetching controller info", func(opts OmadaOptions) error {
			_, err := NewOmadaService().ListClients(context.Background(), opts)
			return err
		}},
		{"plan/login-fail", authOpts, "token mint failed", func(opts OmadaOptions) error {
			_, err := NewOmadaService().Plan(context.Background(), opts, omadaPlanProposal)
			return err
		}},
		{"plan/connect-fail", connectOpts, "fetching controller info", func(opts OmadaOptions) error {
			_, err := NewOmadaService().Plan(context.Background(), opts, omadaPlanProposal)
			return err
		}},
		{"uplink/login-fail", authOpts, "token mint failed", func(opts OmadaOptions) error {
			_, err := NewOmadaService().GetUplinkInfo(context.Background(), opts, []string{"aa:bb:cc:dd:ee:01"})
			return err
		}},
		{"uplink/connect-fail", connectOpts, "fetching controller info", func(opts OmadaOptions) error {
			_, err := NewOmadaService().GetUplinkInfo(context.Background(), opts, []string{"aa:bb:cc:dd:ee:01"})
			return err
		}},
		{"ap-channel-info/login-fail", authOpts, "token mint failed", func(opts OmadaOptions) error {
			_, err := NewOmadaService().ListAPChannels(context.Background(), opts)
			return err
		}},
		{"switch-ports/login-fail", authOpts, "token mint failed", func(opts OmadaOptions) error {
			_, err := NewOmadaService().ListSwitchPorts(context.Background(), opts, "")
			return err
		}},
		{"switch-ports/connect-fail", connectOpts, "fetching controller info", func(opts OmadaOptions) error {
			_, err := NewOmadaService().ListSwitchPorts(context.Background(), opts, "")
			return err
		}},
		{"lan-profiles/login-fail", authOpts, "token mint failed", func(opts OmadaOptions) error {
			_, err := NewOmadaService().ListLanProfiles(context.Background(), opts)
			return err
		}},
		{"lan-profiles/connect-fail", connectOpts, "fetching controller info", func(opts OmadaOptions) error {
			_, err := NewOmadaService().ListLanProfiles(context.Background(), opts)
			return err
		}},
		{"dhcp-users/login-fail", authOpts, "token mint failed", func(opts OmadaOptions) error {
			_, err := NewOmadaService().ListGatewayDHCPUsers(context.Background(), opts, "aa:bb:cc:dd:ee:00")
			return err
		}},
		{"dhcp-users/connect-fail", connectOpts, "fetching controller info", func(opts OmadaOptions) error {
			_, err := NewOmadaService().ListGatewayDHCPUsers(context.Background(), opts, "aa:bb:cc:dd:ee:00")
			return err
		}},
		{"plan-port/login-fail", authOpts, "token mint failed", func(opts OmadaOptions) error {
			_, err := NewOmadaService().PlanPort(context.Background(), opts, OmadaPortProfileRequest{SwitchMAC: "bb:11:22:33:44:55", Port: 8, Native: "trusted"})
			return err
		}},
		{"plan-port/connect-fail", connectOpts, "fetching controller info", func(opts OmadaOptions) error {
			_, err := NewOmadaService().PlanPort(context.Background(), opts, OmadaPortProfileRequest{SwitchMAC: "bb:11:22:33:44:55", Port: 8, Native: "trusted"})
			return err
		}},
		{"apply-port/login-fail", authOpts, "token mint failed", func(opts OmadaOptions) error {
			_, err := NewOmadaService().ApplyPortProfile(context.Background(), opts, OmadaPortProfileRequest{SwitchMAC: "bb:11:22:33:44:55", Port: 8, Native: "trusted"}, false)
			return err
		}},
		{"apply-port/connect-fail", connectOpts, "fetching controller info", func(opts OmadaOptions) error {
			_, err := NewOmadaService().ApplyPortProfile(context.Background(), opts, OmadaPortProfileRequest{SwitchMAC: "bb:11:22:33:44:55", Port: 8, Native: "trusted"}, false)
			return err
		}},
		{"dhcp-server-info/login-fail", authOpts, "token mint failed", func(opts OmadaOptions) error {
			_, err := NewOmadaService().GetDHCPServerInfo(context.Background(), opts, "n1")
			return err
		}},
		{"dhcp-server-info/connect-fail", connectOpts, "fetching controller info", func(opts OmadaOptions) error {
			_, err := NewOmadaService().GetDHCPServerInfo(context.Background(), opts, "n1")
			return err
		}},
		{"dhcp-snoop-status/login-fail", authOpts, "token mint failed", func(opts OmadaOptions) error {
			_, err := NewOmadaService().GetDHCPSnoopStatus(context.Background(), opts)
			return err
		}},
		{"dhcp-snoop-status/connect-fail", connectOpts, "fetching controller info", func(opts OmadaOptions) error {
			_, err := NewOmadaService().GetDHCPSnoopStatus(context.Background(), opts)
			return err
		}},
		{"dhcp-snoops/login-fail", authOpts, "token mint failed", func(opts OmadaOptions) error {
			_, err := NewOmadaService().ListDHCPSnoops(context.Background(), opts)
			return err
		}},
		{"dhcp-snoops/connect-fail", connectOpts, "fetching controller info", func(opts OmadaOptions) error {
			_, err := NewOmadaService().ListDHCPSnoops(context.Background(), opts)
			return err
		}},
		{"lan-multicasts/login-fail", authOpts, "token mint failed", func(opts OmadaOptions) error {
			_, err := NewOmadaService().ListLANMulticasts(context.Background(), opts)
			return err
		}},
		{"lan-multicasts/connect-fail", connectOpts, "fetching controller info", func(opts OmadaOptions) error {
			_, err := NewOmadaService().ListLANMulticasts(context.Background(), opts)
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call(tc.opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestOmadaServiceListNetworks_SitesFetchFails(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		default:
			http.NotFound(w, r)
		}
	})

	_, err := NewOmadaService().ListNetworks(context.Background(), OmadaOptions{
		Host: ts.URL, ClientID: "admin", ClientSecret: "pw", SkipTLSVerify: true,
	})
	if err == nil || !strings.Contains(err.Error(), "fetching sites") {
		t.Fatalf("ListNetworks error = %v, want sites fetch failure", err)
	}
}

func TestOmadaServiceListNetworks_FetchFails(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		default:
			http.NotFound(w, r)
		}
	})

	_, err := NewOmadaService().ListNetworks(context.Background(), OmadaOptions{
		Host: ts.URL, ClientID: "admin", ClientSecret: "pw", SkipTLSVerify: true,
	})
	if err == nil || !strings.Contains(err.Error(), "fetching networks") {
		t.Fatalf("ListNetworks error = %v, want networks fetch failure", err)
	}
}

func TestOmadaServiceListClients(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/openapi/v1/abc123/sites/s1/lan-networks":
			// Open API shape: nested dhcpSettingsVO, no top-level dhcpEnabled
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"n1","name":"Trusted","purpose":"lan","vlan":10,"gatewaySubnet":"10.0.10.1/24","isolation":false,"dhcpSettingsVO":{"enable":true},"deviceMac":"aa:bb:cc:dd:ee:00"}]}`)
		case "/openapi/v1/abc123/sites/s1/networks/client":
			// thin rows: the wire carries only mac/name/type
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"mac":"aa:bb:cc:dd:ee:ff","name":"NAS-01","type":"wired"}]}`)
		case "/openapi/v1/abc123/sites/s1/setting/service/dhcp/user-list":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"ipAddress":"10.0.10.5","macAddress":"aa:bb:cc:dd:ee:ff","name":"NAS-01","netId":"n1","netName":"Trusted"}]}`)
		default:
			http.NotFound(w, r)
		}
	})

	clients, err := NewOmadaService().ListClients(context.Background(), OmadaOptions{
		Host: ts.URL, ClientID: "admin", ClientSecret: "pw", SkipTLSVerify: true,
	})
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if len(clients) != 1 {
		t.Fatalf("got %d clients, want 1", len(clients))
	}
	cl := clients[0]
	if cl.MAC != "aa:bb:cc:dd:ee:ff" || cl.Name != "NAS-01" || cl.Type != "wired" {
		t.Errorf("client identity = %+v", cl)
	}
	// IP, NetworkName, and VLANID are enriched from the DHCP user list.
	if cl.IP != "10.0.10.5" || cl.NetworkName != "Trusted" || cl.VLANID != 10 {
		t.Errorf("client attributes = %+v", cl)
	}
}

func TestOmadaServiceImport(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/openapi/v1/abc123/sites/s1/lan-networks":
			writeOmadaEnvelope(w, 0, `{"totalRows":2,"data":[
				{"id":"n1","name":"Trusted","purpose":"lan","vlan":10,"gatewaySubnet":"10.0.10.1/24","isolation":false,"dhcpSettingsVO":{"enable":true},"deviceMac":"aa:bb:cc:dd:ee:00"},
				{"id":"n2","name":"IoT","purpose":"lan","vlan":20,"gatewaySubnet":"10.0.20.1/24","isolation":true,"dhcpSettingsVO":{"enable":false},"deviceMac":"aa:bb:cc:dd:ee:00"}]}`)
		case "/openapi/v1/abc123/sites/s1/acls/osg-acls":
			writeOmadaEnvelope(w, 0, `{"totalRows":0,"data":[]}`)
		case "/openapi/v1/abc123/sites/s1/acls/osw-acls":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"a1","description":"Block IoT","status":true,"policy":0,"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1"],"index":1}]}`)
		case "/openapi/v1/abc123/sites/s1/networks/devices":
			writeOmadaEnvelope(w, 0, `[{"id":"d1","name":"GW-CORE","model":"GW-CORE","type":"gateway","mac":"aa:bb:cc:dd:ee:00","ip":"10.0.0.254"}]`)
		case "/openapi/v1/abc123/sites/s1/networks/client":
			// thin rows: the wire carries only mac/name/type
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"mac":"aa:bb:cc:dd:ee:ff","name":"NAS-01","type":"wired"}]}`)
		case "/openapi/v1/abc123/sites/s1/setting/service/dhcp/user-list":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"ipAddress":"10.0.10.5","macAddress":"aa:bb:cc:dd:ee:ff","name":"NAS-01","netId":"n1","netName":"Trusted"}]}`)
		default:
			http.NotFound(w, r)
		}
	})

	imp, err := NewOmadaService().Import(context.Background(), OmadaOptions{
		Host: ts.URL, ClientID: "admin", ClientSecret: "pw", SkipTLSVerify: true,
	})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if imp.Site != "HQ" {
		t.Errorf("site = %q, want HQ", imp.Site)
	}
	if imp.ControllerVersion != "6.4.5.1" {
		t.Errorf("controller_version = %q, want 6.4.5.1", imp.ControllerVersion)
	}
	if imp.NetworkCount != 2 || imp.ACLRuleCount != 1 || imp.ClientCount != 1 {
		t.Errorf("counts = nets %d, acls %d, clients %d; want 2/1/1", imp.NetworkCount, imp.ACLRuleCount, imp.ClientCount)
	}
	if len(imp.Warnings) != 0 {
		t.Errorf("warnings = %v, want none", imp.Warnings)
	}
	if imp.Spec == nil {
		t.Fatal("spec is nil")
	}
	if len(imp.Spec.Networks) != 2 || imp.Spec.Networks[0].Name != "trusted" || imp.Spec.Networks[0].CIDR != "10.0.10.0/24" {
		t.Errorf("spec networks = %+v, want sanitized trusted/10.0.10.0/24", imp.Spec.Networks)
	}
	if len(imp.Spec.Policies) != 1 || imp.Spec.Policies[0].From != "iot" || imp.Spec.Policies[0].To != "trusted" || imp.Spec.Policies[0].Action != "deny" {
		t.Errorf("spec policies = %+v, want iot->trusted deny", imp.Spec.Policies)
	}
	hasIsolation := false
	for _, a := range imp.Spec.Assertions {
		if a.Type == "isolation" && a.From == "iot" && a.To == "trusted" {
			hasIsolation = true
		}
	}
	if !hasIsolation {
		t.Errorf("assertions = %+v, want iot->trusted isolation", imp.Spec.Assertions)
	}
}

func TestOmadaServiceImport_Warnings(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/openapi/v1/abc123/sites/s1/lan-networks":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"n1","name":"Trusted","gatewaySubnet":"10.0.10.1/24"}]}`)
		case "/openapi/v1/abc123/sites/s1/acls/osg-acls", "/openapi/v1/abc123/sites/s1/acls/osw-acls":
			writeOmadaEnvelope(w, -1000, "null")
		case "/openapi/v1/abc123/sites/s1/networks/client":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"mac":"aa:bb:cc:dd:ee:ff","name":"NAS-01","type":"wired"}]}`)
		case "/openapi/v1/abc123/sites/s1/setting/service/dhcp/user-list":
			writeOmadaEnvelope(w, 0, `{"totalRows":0,"data":[]}`)
		case "/openapi/v1/abc123/sites/s1/networks/devices":
			writeOmadaEnvelope(w, 0, `[]`)
		default:
			http.NotFound(w, r)
		}
	})

	imp, err := NewOmadaService().Import(context.Background(), OmadaOptions{
		Host: ts.URL, ClientID: "admin", ClientSecret: "pw", SkipTLSVerify: true,
	})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if len(imp.Warnings) != 2 {
		t.Fatalf("warnings = %v, want ACL + gateway ACL fetch warnings", imp.Warnings)
	}
	for _, w := range imp.Warnings {
		if strings.Contains(w, "device inventory") {
			t.Errorf("warnings = %v, want no device inventory warning", imp.Warnings)
		}
	}
	if imp.ACLRuleCount != 0 || imp.NetworkCount != 1 {
		t.Errorf("counts = acls %d, nets %d; want 0/1", imp.ACLRuleCount, imp.NetworkCount)
	}
}

func TestOmadaServiceImport_NetworksFetchFails(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		default:
			http.NotFound(w, r)
		}
	})

	_, err := NewOmadaService().Import(context.Background(), OmadaOptions{
		Host: ts.URL, ClientID: "admin", ClientSecret: "pw", SkipTLSVerify: true,
	})
	if err == nil || !strings.Contains(err.Error(), "fetching networks") {
		t.Fatalf("Import error = %v, want networks fetch failure", err)
	}
}

func TestOmadaServiceListClients_FetchFails(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		default:
			http.NotFound(w, r)
		}
	})

	_, err := NewOmadaService().ListClients(context.Background(), OmadaOptions{
		Host: ts.URL, ClientID: "admin", ClientSecret: "pw", SkipTLSVerify: true,
	})
	if err == nil || !strings.Contains(err.Error(), "fetching clients") {
		t.Fatalf("ListClients error = %v, want clients fetch failure", err)
	}
}

const omadaPlanProposal = `version: 1
site: HQ
networks:
  - name: trusted
    cidr: 10.0.10.0/24
  - name: iot
    cidr: 10.0.20.0/24
  - name: guest
    cidr: 10.0.30.0/24
  - name: wan
    cidr: 10.0.0.0/24
policies:
  - name: block-iot
    from: iot
    to: trusted
    action: deny
  - name: allow-iot-guest
    from: iot
    to: guest
    action: allow
  - name: block-guest
    from: guest
    to: trusted
    action: deny
  - name: block-dmz
    from: iot
    to: dmz
    action: deny
assertions: []
`

func TestOmadaServicePlanApplyLAN(t *testing.T) {
	st := omadaPortStateFresh()
	ts := omadaTestServer(t, omadaPortBaseHandler(t, st))
	svc := NewOmadaService()
	ctx := context.Background()
	opts := omadaPortOpts(ts.URL)
	plan, err := svc.PlanLAN(ctx, opts, OmadaLANRequest{Name: "trusted"})
	if err != nil {
		t.Fatalf("PlanLAN existing: %v", err)
	}
	if plan.Action != "unchanged" && plan.Action != "update" && plan.Action != "create" {
		t.Errorf("plan action = %q", plan.Action)
	}
	create, err := svc.PlanLAN(ctx, opts, OmadaLANRequest{Name: "newlan", VLAN: 99, GatewaySubnet: "10.0.99.1/24"})
	if err != nil {
		t.Fatalf("PlanLAN create: %v", err)
	}
	if create.Action != "create" {
		t.Errorf("create action = %q", create.Action)
	}
	if _, err := svc.PlanLAN(ctx, opts, OmadaLANRequest{}); err == nil {
		t.Fatal("expected name required")
	}
	dry, err := svc.ApplyLAN(ctx, opts, OmadaLANRequest{Name: "newlan", VLAN: 99, GatewaySubnet: "10.0.99.1/24"}, true)
	if err != nil {
		t.Fatalf("ApplyLAN dry: %v", err)
	}
	if !dry.DryRun || dry.Outcome != "create" && dry.Outcome != "created" {
		t.Errorf("dry = %+v", dry)
	}
	del, err := svc.PlanLAN(ctx, opts, OmadaLANRequest{Name: "trusted", Delete: true})
	if err != nil {
		t.Fatalf("PlanLAN delete: %v", err)
	}
	if del.Action != "delete" && del.Action != "unchanged" {
		t.Errorf("delete action = %q", del.Action)
	}
	missing, err := svc.PlanLAN(ctx, opts, OmadaLANRequest{Name: "no-such-lan", Delete: true})
	if err != nil || missing.Action != "unchanged" {
		t.Fatalf("delete missing = %+v, %v", missing, err)
	}
}

func TestOmadaServiceApplyLAN_Mutations(t *testing.T) {
	st := omadaPortStateFresh()
	created := false
	h := omadaPortBaseHandler(t, st)
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/lan-networks") && r.Method == http.MethodPost {
			created = true
			writeOmadaEnvelope(w, 0, `{"id":"n-new"}`)
			return
		}
		if strings.Contains(r.URL.Path, "/lan-networks/") && r.Method == http.MethodPut {
			writeOmadaEnvelope(w, 0, `{}`)
			return
		}
		if strings.Contains(r.URL.Path, "/lan-networks/") && r.Method == http.MethodDelete {
			writeOmadaEnvelope(w, 0, `{}`)
			return
		}
		h(w, r)
	})
	svc := NewOmadaService()
	ctx := context.Background()
	opts := omadaPortOpts(ts.URL)
	res, err := svc.ApplyLAN(ctx, opts, OmadaLANRequest{Name: "newlan", VLAN: 99, GatewaySubnet: "10.0.99.1/24"}, false)
	if err != nil {
		t.Fatalf("create apply: %v", err)
	}
	if res.Outcome != "created" || !created {
		t.Errorf("create = %+v created=%v", res, created)
	}
	// existing trusted network should update or stay unchanged
	res, err = svc.ApplyLAN(ctx, opts, OmadaLANRequest{Name: "trusted", VLAN: 1, Isolated: true}, false)
	if err != nil {
		t.Fatalf("update apply: %v", err)
	}
	if res.Outcome != "updated" && res.Outcome != "unchanged" {
		t.Errorf("update = %+v", res)
	}
	res, err = svc.ApplyLAN(ctx, opts, OmadaLANRequest{Name: "trusted", Delete: true}, false)
	if err != nil {
		t.Fatalf("delete apply: %v", err)
	}
	if res.Outcome != "deleted" && res.Outcome != "unchanged" {
		t.Errorf("delete = %+v", res)
	}
}

func TestOmadaServicePlanApplyLAN_Errors(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi/authorize/token" {
			writeOmadaEnvelope(w, 0, `{"accessToken":"t"}`)
			return
		}
		writeOmadaEnvelope(w, -33004, `null`)
	})
	opts := omadaPortOpts(ts.URL)
	if _, err := NewOmadaService().PlanLAN(context.Background(), opts, OmadaLANRequest{Name: "iot"}); err == nil {
		t.Fatal("expected PlanLAN fetch error")
	}
	if _, err := NewOmadaService().ApplyLAN(context.Background(), opts, OmadaLANRequest{Name: "iot"}, false); err == nil {
		t.Fatal("expected ApplyLAN fetch error")
	}
}

func TestOmadaServiceApplyLAN_CreateFails(t *testing.T) {
	st := omadaPortStateFresh()
	h := omadaPortBaseHandler(t, st)
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/lan-networks") && r.Method == http.MethodPost {
			writeOmadaEnvelope(w, -1001, `null`)
			return
		}
		h(w, r)
	})
	_, err := NewOmadaService().ApplyLAN(context.Background(), omadaPortOpts(ts.URL), OmadaLANRequest{Name: "newlan", VLAN: 99, GatewaySubnet: "10.0.99.1/24"}, false)
	if err == nil {
		t.Fatal("expected create failure")
	}
}

// The plan session can succeed while the apply's second session fails; the
// error must surface from the apply, after the plan already committed.
func TestOmadaServiceApplyLAN_SessionFailsAfterPlan(t *testing.T) {
	st := omadaPortStateFresh()
	h := omadaPortBaseHandler(t, st)
	tokens := 0
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi/authorize/token" {
			tokens++
			if tokens > 1 {
				writeOmadaEnvelope(w, -44106, `null`)
				return
			}
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
			return
		}
		h(w, r)
	})
	_, err := NewOmadaService().ApplyLAN(context.Background(), omadaPortOpts(ts.URL),
		OmadaLANRequest{Name: "newlan", VLAN: 99, GatewaySubnet: "10.0.99.1/24"}, false)
	if err == nil {
		t.Fatal("expected the apply session to fail")
	}
}

func TestOmadaServiceApplyLAN_UpdateDeleteFail(t *testing.T) {
	st := omadaPortStateFresh()
	h := omadaPortBaseHandler(t, st)
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/lan-networks/") && (r.Method == http.MethodPut || r.Method == http.MethodDelete) {
			writeOmadaEnvelope(w, -1001, `null`)
			return
		}
		h(w, r)
	})
	svc := NewOmadaService()
	ctx := context.Background()
	opts := omadaPortOpts(ts.URL)
	if _, err := svc.ApplyLAN(ctx, opts, OmadaLANRequest{Name: "trusted", VLAN: 2}, false); err == nil {
		t.Fatal("expected update failure")
	}
	if _, err := svc.ApplyLAN(ctx, opts, OmadaLANRequest{Name: "trusted", Delete: true}, false); err == nil {
		t.Fatal("expected delete failure")
	}
}

// A failure on the site's network read must fail both the LAN plan and the
// inventory's fatal network read.
func TestOmadaServicePlanLAN_GetNetworksFails(t *testing.T) {
	st := omadaPortStateFresh()
	st.NetworksFailAfter = 1
	ts := omadaTestServer(t, omadaPortBaseHandler(t, st))
	if _, err := NewOmadaService().PlanLAN(context.Background(), omadaPortOpts(ts.URL), OmadaLANRequest{Name: "iot"}); err == nil {
		t.Fatal("expected PlanLAN fetch error")
	}
}

func TestOmadaServiceInventory_FetchFails(t *testing.T) {
	st := omadaPortStateFresh()
	st.NetworksFailAfter = 1
	ts := omadaTestServer(t, omadaPortBaseHandler(t, st))
	if _, err := NewOmadaService().Inventory(context.Background(), omadaPortOpts(ts.URL)); err == nil {
		t.Fatal("expected Inventory fetch error")
	}
}

// A request that matches the controller's current LAN must plan unchanged
// with the existing network id.
func TestOmadaServicePlanLAN_Unchanged(t *testing.T) {
	st := omadaPortStateFresh()
	ts := omadaTestServer(t, omadaPortBaseHandler(t, st))
	plan, err := NewOmadaService().PlanLAN(context.Background(), omadaPortOpts(ts.URL),
		OmadaLANRequest{Name: "trusted", VLAN: 1, GatewaySubnet: "10.0.10.1/24"})
	if err != nil {
		t.Fatalf("PlanLAN: %v", err)
	}
	if plan.Action != "unchanged" || plan.ID != "n1" {
		t.Errorf("plan = %+v, want unchanged n1", plan)
	}
}

func TestOmadaServiceListGatewayDHCPUsers_FetchFails(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		default:
			writeOmadaEnvelope(w, -33004, `null`)
		}
	})
	_, err := NewOmadaService().ListGatewayDHCPUsers(context.Background(), omadaPortOpts(ts.URL), "aa:bb:cc:dd:ee:00")
	if err == nil || !strings.Contains(err.Error(), "fetching gateway DHCP users") {
		t.Fatalf("error = %v, want gateway DHCP users fetch prefix", err)
	}
}

func omadaSSIDHandler(t *testing.T, ssids string, failGroups, failSSIDs, failWrites bool) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case r.URL.Path == "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case strings.Contains(r.URL.Path, "/wlan-groups"):
			if failGroups {
				writeOmadaEnvelope(w, -33004, `null`)
				return
			}
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"g1","name":"Default"}]}`)
		case strings.HasSuffix(r.URL.Path, "/ssids") && r.Method == http.MethodGet:
			if failSSIDs {
				writeOmadaEnvelope(w, -33004, `null`)
				return
			}
			writeOmadaEnvelope(w, 0, ssids)
		case strings.HasSuffix(r.URL.Path, "/ssids") && r.Method == http.MethodPost:
			if failWrites {
				writeOmadaEnvelope(w, -1001, `null`)
				return
			}
			writeOmadaEnvelope(w, 0, `{"id":"s-new"}`)
		case strings.Contains(r.URL.Path, "/ssids/") && r.Method == http.MethodPut:
			if failWrites {
				writeOmadaEnvelope(w, -1001, `null`)
				return
			}
			writeOmadaEnvelope(w, 0, `{}`)
		case strings.Contains(r.URL.Path, "/ssids/") && r.Method == http.MethodDelete:
			if failWrites {
				writeOmadaEnvelope(w, -1001, `null`)
				return
			}
			writeOmadaEnvelope(w, 0, `{}`)
		default:
			writeOmadaEnvelope(w, -1, `null`)
		}
	}
}

func TestOmadaServiceListPlanApplySSID(t *testing.T) {
	const listed = `{"totalRows":1,"data":[{"id":"s1","name":"iot-wifi","ssid":"iot","enable":true,"vlanId":60,"security":"wpa2","wlanGroupId":"g1"}]}`
	ts := omadaTestServer(t, omadaSSIDHandler(t, listed, false, false, false))
	svc := NewOmadaService()
	ctx := context.Background()
	opts := omadaPortOpts(ts.URL)

	inv, err := svc.ListSSIDs(ctx, opts)
	if err != nil || len(inv.SSIDs) != 1 || inv.SSIDs[0].SSID != "iot" || len(inv.Groups) != 1 {
		t.Fatalf("ListSSIDs = %+v %v", inv, err)
	}
	unchanged, err := svc.PlanSSID(ctx, opts, OmadaSSIDRequest{Name: "iot-wifi", SSID: "iot", Enabled: true, VLAN: 60, Security: "wpa2", WLANGroup: "Default"})
	if err != nil || unchanged.Action != "unchanged" {
		t.Fatalf("unchanged = %+v %v", unchanged, err)
	}
	create, err := svc.PlanSSID(ctx, opts, OmadaSSIDRequest{SSID: "guest", VLAN: 70})
	if err != nil || create.Action != "create" {
		t.Fatalf("create = %+v %v", create, err)
	}
	update, err := svc.PlanSSID(ctx, opts, OmadaSSIDRequest{Name: "iot-wifi", VLAN: 61, Enabled: true})
	if err != nil || update.Action != "update" {
		t.Fatalf("update = %+v %v", update, err)
	}
	del, err := svc.PlanSSID(ctx, opts, OmadaSSIDRequest{Name: "iot-wifi", Delete: true})
	if err != nil || del.Action != "delete" {
		t.Fatalf("delete = %+v %v", del, err)
	}
	missing, err := svc.PlanSSID(ctx, opts, OmadaSSIDRequest{Name: "nope", Delete: true})
	if err != nil || missing.Action != "unchanged" {
		t.Fatalf("delete missing = %+v %v", missing, err)
	}
	if _, err := svc.PlanSSID(ctx, opts, OmadaSSIDRequest{}); err == nil {
		t.Fatal("expected name or ssid required")
	}
	dry, err := svc.ApplySSID(ctx, opts, OmadaSSIDRequest{SSID: "guest", VLAN: 70}, true)
	if err != nil || !dry.DryRun || dry.Outcome != "create" {
		t.Fatalf("dry = %+v %v", dry, err)
	}
	created, err := svc.ApplySSID(ctx, opts, OmadaSSIDRequest{SSID: "guest", VLAN: 70}, false)
	if err != nil || created.Outcome != "created" || created.ID != "s-new" {
		t.Fatalf("created = %+v %v", created, err)
	}
	updated, err := svc.ApplySSID(ctx, opts, OmadaSSIDRequest{Name: "iot-wifi", VLAN: 61, Enabled: true}, false)
	if err != nil || updated.Outcome != "updated" {
		t.Fatalf("updated = %+v %v", updated, err)
	}
	deleted, err := svc.ApplySSID(ctx, opts, OmadaSSIDRequest{Name: "iot-wifi", Delete: true}, false)
	if err != nil || deleted.Outcome != "deleted" {
		t.Fatalf("deleted = %+v %v", deleted, err)
	}
}

func TestOmadaServiceSSID_Errors(t *testing.T) {
	opts := omadaPortOpts(omadaTestServer(t, omadaSSIDHandler(t, `{"totalRows":0,"data":[]}`, true, false, false)).URL)
	if _, err := NewOmadaService().ListSSIDs(context.Background(), opts); err == nil {
		t.Fatal("expected list groups error")
	}
	if _, err := NewOmadaService().PlanSSID(context.Background(), opts, OmadaSSIDRequest{Name: "x"}); err == nil {
		t.Fatal("expected plan groups error after ssid list")
	}
	failSSIDs := omadaPortOpts(omadaTestServer(t, omadaSSIDHandler(t, ``, false, true, false)).URL)
	if _, err := NewOmadaService().ListSSIDs(context.Background(), failSSIDs); err == nil {
		t.Fatal("expected list ssids error")
	}
	if _, err := NewOmadaService().PlanSSID(context.Background(), failSSIDs, OmadaSSIDRequest{Name: "x"}); err == nil {
		t.Fatal("expected plan ssid list error")
	}
	if _, err := NewOmadaService().ApplySSID(context.Background(), failSSIDs, OmadaSSIDRequest{Name: "x"}, false); err == nil {
		t.Fatal("expected apply plan error")
	}
}

// Controller write failures must surface from every SSID mutation outcome,
// after the plan already succeeded.
func TestOmadaServiceSSID_WriteFails(t *testing.T) {
	const listed = `{"totalRows":1,"data":[{"id":"s1","name":"iot-wifi","ssid":"iot","enable":true,"vlanId":60,"security":"wpa2","wlanGroupId":"g1"}]}`
	ts := omadaTestServer(t, omadaSSIDHandler(t, listed, false, false, true))
	svc := NewOmadaService()
	ctx := context.Background()
	opts := omadaPortOpts(ts.URL)
	if _, err := svc.ApplySSID(ctx, opts, OmadaSSIDRequest{SSID: "guest", VLAN: 70}, false); err == nil {
		t.Error("expected create failure")
	}
	if _, err := svc.ApplySSID(ctx, opts, OmadaSSIDRequest{Name: "iot-wifi", VLAN: 61, Enabled: true}, false); err == nil {
		t.Error("expected update failure")
	}
	if _, err := svc.ApplySSID(ctx, opts, OmadaSSIDRequest{Name: "iot-wifi", Delete: true}, false); err == nil {
		t.Error("expected delete failure")
	}
}

// The apply session's WLAN-group read can fail after the plan session
// succeeded; the mutation must stop with the fetch error.
func TestOmadaServiceSSID_ApplySessionFails(t *testing.T) {
	const listed = `{"totalRows":1,"data":[{"id":"s1","name":"iot-wifi","ssid":"iot","enable":true,"vlanId":60,"security":"wpa2","wlanGroupId":"g1"}]}`
	groupsGets := 0
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/wlan-groups") {
			groupsGets++
			if groupsGets > 1 {
				writeOmadaEnvelope(w, -33004, `null`)
				return
			}
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"g1","name":"Default"}]}`)
			return
		}
		omadaSSIDHandler(t, listed, false, false, false)(w, r)
	})
	if _, err := NewOmadaService().ApplySSID(context.Background(), omadaPortOpts(ts.URL), OmadaSSIDRequest{SSID: "guest", VLAN: 70}, false); err == nil {
		t.Fatal("expected the apply session's wlan-groups fetch to fail")
	}
}

func TestResolveWLANGroupID(t *testing.T) {
	groups := []omadabackend.WLANGroup{{ID: "g1", Name: "Default"}, {ID: "g2", Name: "Guests"}}
	if got := resolveWLANGroupID(groups, "guests"); got != "g2" {
		t.Errorf("by name = %q, want g2", got)
	}
	if got := resolveWLANGroupID(groups, "G1"); got != "g1" {
		t.Errorf("by id = %q, want g1", got)
	}
	if got := resolveWLANGroupID(groups, "no-such-group"); got != "no-such-group" {
		t.Errorf("unknown name = %q, want fallthrough to the name", got)
	}
	if got := resolveWLANGroupID(nil, ""); got != "" {
		t.Errorf("empty name = %q, want empty", got)
	}
}
