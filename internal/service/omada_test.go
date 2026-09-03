package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	providers "github.com/jpvelasco/nyx/internal/providers"
	omadaprovider "github.com/jpvelasco/nyx/internal/providers/omada"
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
				{"id":"n1","name":"Trusted","purpose":"lan","vlan":10,"gatewaySubnet":"10.0.10.1/24","isolation":false,"dhcpSettingsVO":{"enable":true},"deviceMac":"aa:bb:cc:dd:ee:00"},
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
	iot := nets[1]
	if iot.VLANID != 20 || iot.DHCPEnabled || !iot.Isolated {
		t.Errorf("iot = %+v, want vlan 20, dhcp off, isolated", iot)
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

func TestOmadaServiceListACLs(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/openapi/v1/abc123/sites/s1/lan-networks":
			writeOmadaEnvelope(w, 0, `{"totalRows":3,"data":[
				{"id":"n1","name":"Trusted","gatewaySubnet":"10.0.10.1/24"},
				{"id":"n2","name":"IoT","gatewaySubnet":"10.0.20.1/24"},
				{"id":"n3","name":"Guest","gatewaySubnet":"10.0.30.1/24"}]}`)
		case "/openapi/v1/abc123/sites/s1/acls/osg-acls":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"g1","description":"Deny Guest","status":false,"policy":0,"protocols":[6],"sourceType":"network","sourceIds":["n3"],"destinationType":"network","destinationIds":["n1"],"index":5}]}`)
		case "/openapi/v1/abc123/sites/s1/acls/osw-acls":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"a1","description":"Block IoT","status":true,"policy":0,"protocols":[256],"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1"],"index":1}]}`)
		default:
			http.NotFound(w, r)
		}
	})

	rules, err := NewOmadaService().ListACLs(context.Background(), OmadaOptions{
		Host: ts.URL, ClientID: "admin", ClientSecret: "pw", SkipTLSVerify: true,
	})
	if err != nil {
		t.Fatalf("ListACLs: %v", err)
	}
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2 (switch + gateway)", len(rules))
	}
	sw := rules[0]
	if sw.Name != "Block IoT" || !sw.Enabled || sw.Policy != "drop" || sw.Protocols != "all" {
		t.Errorf("switch rule = %+v, want enabled drop all", sw)
	}
	if sw.SourceType != "network" || sw.SourceName != "IoT" || sw.DestName != "Trusted" || sw.Index != 1 {
		t.Errorf("switch rule endpoints = %+v", sw)
	}
	gw := rules[1]
	if gw.Name != "Deny Guest" || gw.Enabled || gw.Protocols != "6" || gw.Index != 5 {
		t.Errorf("gateway rule = %+v, want disabled proto-6 rule index 5", gw)
	}
}

func TestOmadaServiceListACLs_GatewayFetchFails(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/openapi/v1/abc123/sites/s1/acls/osg-acls":
			http.NotFound(w, r)
			return
		case "/openapi/v1/abc123/sites/s1/acls/osw-acls":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"a1","description":"Block IoT"}]}`)
		default:
			http.NotFound(w, r)
		}
	})

	_, err := NewOmadaService().ListACLs(context.Background(), OmadaOptions{
		Host: ts.URL, ClientID: "admin", ClientSecret: "pw", SkipTLSVerify: true,
	})
	if err == nil || !strings.Contains(err.Error(), "gateway ACL") {
		t.Fatalf("ListACLs error = %v, want gateway ACL failure", err)
	}
}

func TestOmadaServiceListACLs_SwitchFetchFails(t *testing.T) {
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

	_, err := NewOmadaService().ListACLs(context.Background(), OmadaOptions{
		Host: ts.URL, ClientID: "admin", ClientSecret: "pw", SkipTLSVerify: true,
	})
	if err == nil || !strings.Contains(err.Error(), "fetching ACL rules") {
		t.Fatalf("ListACLs error = %v, want switch ACL failure", err)
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

func TestOmadaServicePlan(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/openapi/v1/abc123/sites/s1/lan-networks":
			writeOmadaEnvelope(w, 0, `{"totalRows":4,"data":[
				{"id":"n1","name":"Trusted","gatewaySubnet":"10.0.10.1/24"},
				{"id":"n2","name":"IoT","gatewaySubnet":"10.0.20.1/24"},
				{"id":"n3","name":"Guest","gatewaySubnet":"10.0.30.1/24"},
				{"id":"n4","name":"WAN","gatewaySubnet":"10.0.0.1/24"}]}`)
		case "/openapi/v1/abc123/sites/s1/acls/osg-acls":
			writeOmadaEnvelope(w, 0, `{"totalRows":2,"data":[
				{"id":"g1","description":"Block IoT Guest","status":true,"policy":0,"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n3"],"index":1},
				{"id":"g2","description":"IoT WAN","status":true,"policy":1,"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n4"],"index":2}]}`)
		case "/openapi/v1/abc123/sites/s1/acls/osw-acls":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"a1","description":"Block IoT","status":true,"policy":0,"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1"],"index":1}]}`)
		default:
			http.NotFound(w, r)
		}
	})

	plan, err := NewOmadaService().Plan(context.Background(), OmadaOptions{
		Host: ts.URL, ClientID: "admin", ClientSecret: "pw", SkipTLSVerify: true,
	}, omadaPlanProposal)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if plan.Site != "HQ" || plan.ProposedSite != "HQ" {
		t.Errorf("sites = current %q proposed %q, want HQ/HQ", plan.Site, plan.ProposedSite)
	}
	if plan.CurrentRules != 3 || plan.ProposedRules != 4 {
		t.Errorf("counts = current %d proposed %d, want 3/4", plan.CurrentRules, plan.ProposedRules)
	}
	if len(plan.Unchanged) != 1 || plan.Unchanged[0].From != "iot" || plan.Unchanged[0].To != "trusted" || plan.Unchanged[0].Action != "deny" {
		t.Errorf("unchanged = %+v, want iot->trusted deny", plan.Unchanged)
	}
	if len(plan.ToChange) != 1 || plan.ToChange[0].From != "iot" || plan.ToChange[0].To != "guest" ||
		plan.ToChange[0].CurrentAction != "deny" || plan.ToChange[0].ProposedAction != "allow" {
		t.Errorf("to_change = %+v, want iot->guest deny->allow", plan.ToChange)
	}
	if len(plan.ToAdd) != 2 {
		t.Fatalf("to_add = %+v, want 2", plan.ToAdd)
	}
	addKeys := map[string]string{}
	for _, d := range plan.ToAdd {
		addKeys[d.From+"|"+d.To] = d.Action
	}
	if addKeys["guest|trusted"] != "deny" || addKeys["iot|dmz"] != "deny" {
		t.Errorf("to_add = %+v, want guest->trusted and iot->dmz deny", plan.ToAdd)
	}
	if len(plan.ToRemove) != 1 || plan.ToRemove[0].From != "iot" || plan.ToRemove[0].To != "wan" || plan.ToRemove[0].Action != "allow" {
		t.Errorf("to_remove = %+v, want iot->wan allow", plan.ToRemove)
	}
	if len(plan.Warnings) != 1 || !strings.Contains(plan.Warnings[0], "dmz") {
		t.Errorf("warnings = %v, want dmz not declared", plan.Warnings)
	}
}

func TestOmadaServicePlan_InvalidProposal(t *testing.T) {
	svc := &OmadaService{NewClient: func(ctx context.Context, host string, skipTLSVerify bool, caCertPath string) (*omadabackend.Client, error) {
		t.Error("NewClient called; proposal must be validated before any controller request")
		return nil, errors.New("unexpected client")
	}}
	_, err := svc.Plan(context.Background(), OmadaOptions{Host: "https://omada.local"}, "version: 1\nsite: HQ\nnot: [valid")
	if err == nil || !strings.Contains(err.Error(), "parsing spec YAML") {
		t.Fatalf("Plan error = %v, want spec parse failure", err)
	}
}

func TestOmadaServicePlan_NetworksFetchFails(t *testing.T) {
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

	_, err := NewOmadaService().Plan(context.Background(), OmadaOptions{
		Host: ts.URL, ClientID: "admin", ClientSecret: "pw", SkipTLSVerify: true,
	}, omadaPlanProposal)
	if err == nil || !strings.Contains(err.Error(), "fetching networks") {
		t.Fatalf("Plan error = %v, want networks fetch failure", err)
	}
}

func TestOmadaServicePlan_GatewayACLsFetchFails(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/openapi/v1/abc123/sites/s1/lan-networks":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"n1","name":"Trusted","gatewaySubnet":"10.0.10.1/24"}]}`)
		case "/openapi/v1/abc123/sites/s1/acls/osg-acls":
			http.NotFound(w, r)
			return
		case "/openapi/v1/abc123/sites/s1/acls/osw-acls":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"a1","description":"Block","status":true,"policy":0}]}`)
		default:
			http.NotFound(w, r)
		}
	})

	_, err := NewOmadaService().Plan(context.Background(), OmadaOptions{
		Host: ts.URL, ClientID: "admin", ClientSecret: "pw", SkipTLSVerify: true,
	}, omadaPlanProposal)
	if err == nil || !strings.Contains(err.Error(), "gateway ACL") {
		t.Fatalf("Plan error = %v, want gateway ACL fetch failure", err)
	}
}

func TestOmadaServicePlan_ACLsFetchFails(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/openapi/v1/abc123/sites/s1/lan-networks":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"n1","name":"Trusted","gatewaySubnet":"10.0.10.1/24"}]}`)
		default:
			http.NotFound(w, r)
		}
	})

	_, err := NewOmadaService().Plan(context.Background(), OmadaOptions{
		Host: ts.URL, ClientID: "admin", ClientSecret: "pw", SkipTLSVerify: true,
	}, omadaPlanProposal)
	if err == nil || !strings.Contains(err.Error(), "fetching ACL rules") {
		t.Fatalf("Plan error = %v, want switch ACL fetch failure", err)
	}
}

func TestDiffPolicies(t *testing.T) {
	current := []intent.Policy{
		{Name: "a", From: "iot", To: "trusted", Action: "deny"},
		{Name: "b", From: "iot", To: "wan", Action: "allow"},
		{Name: "c", From: "", To: "", Action: "deny"},
	}
	proposed := []intent.Policy{
		{Name: "a", From: "iot", To: "trusted", Action: "deny"},
		{Name: "b", From: "iot", To: "wan", Action: "deny"},
		{Name: "d", From: "guest", To: "trusted", Action: "deny"},
	}

	plan := diffPolicies(current, proposed, []string{"trusted", "iot", "guest", "wan"})
	if len(plan.Unchanged) != 1 || plan.Unchanged[0].From != "iot" || plan.Unchanged[0].To != "trusted" {
		t.Errorf("unchanged = %+v, want iot->trusted", plan.Unchanged)
	}
	if len(plan.ToChange) != 1 || plan.ToChange[0].CurrentAction != "allow" || plan.ToChange[0].ProposedAction != "deny" {
		t.Errorf("to_change = %+v, want allow->deny", plan.ToChange)
	}
	if len(plan.ToAdd) != 1 || plan.ToAdd[0].From != "guest" || plan.ToAdd[0].To != "trusted" {
		t.Errorf("to_add = %+v, want guest->trusted", plan.ToAdd)
	}
	if len(plan.ToRemove) != 1 || plan.ToRemove[0].From != "" || plan.ToRemove[0].To != "" || plan.ToRemove[0].Action != "deny" {
		t.Errorf("to_remove = %+v, want empty-endpoint deny (iot->wan is a change)", plan.ToRemove)
	}
	if plan.CurrentRules != 3 || plan.ProposedRules != 3 {
		t.Errorf("counts = current %d proposed %d, want 3/3", plan.CurrentRules, plan.ProposedRules)
	}

	t.Run("empty current", func(t *testing.T) {
		plan := diffPolicies(nil, proposed, nil)
		if len(plan.ToAdd) != 3 || len(plan.ToRemove) != 0 || len(plan.Unchanged) != 0 || len(plan.ToChange) != 0 {
			t.Errorf("empty current plan = %+v, want all 3 proposed as adds", plan)
		}
		if len(plan.Warnings) != 6 {
			t.Errorf("warnings = %v, want 6 undeclared endpoints", plan.Warnings)
		}
	})

	t.Run("empty proposed", func(t *testing.T) {
		plan := diffPolicies(current, nil, nil)
		if len(plan.ToRemove) != 3 || len(plan.ToAdd) != 0 || len(plan.Unchanged) != 0 || len(plan.ToChange) != 0 {
			t.Errorf("empty proposed plan = %+v, want all 3 current as removals", plan)
		}
	})

	t.Run("duplicate endpoints are all reported", func(t *testing.T) {
		dup := append([]intent.Policy{}, proposed...)
		dup = append(dup, intent.Policy{Name: "dup", From: "guest", To: "trusted", Action: "allow"})
		plan := diffPolicies(current, dup, nil)
		if len(plan.ToChange) != 1 {
			t.Errorf("to_change = %+v, want iot->wan change only", plan.ToChange)
		}
		if len(plan.ToAdd) != 2 {
			t.Fatalf("to_add = %+v, want both guest->trusted rules", plan.ToAdd)
		}
		actions := map[string]bool{}
		for _, d := range plan.ToAdd {
			actions[d.Action] = true
		}
		if !actions["deny"] || !actions["allow"] {
			t.Errorf("to_add = %+v, want one deny and one allow", plan.ToAdd)
		}
		if len(plan.ToRemove) != 1 || plan.ToRemove[0].From != "" {
			t.Errorf("to_remove = %+v, want only the empty-endpoint rule", plan.ToRemove)
		}
	})

	t.Run("duplicate current rules are not hidden", func(t *testing.T) {
		cur := []intent.Policy{
			{Name: "x1", From: "iot", To: "wan", Action: "deny"},
			{Name: "x2", From: "iot", To: "wan", Action: "allow"},
		}
		prop := []intent.Policy{{Name: "x1", From: "iot", To: "wan", Action: "deny"}}
		plan := diffPolicies(cur, prop, nil)
		if len(plan.Unchanged) != 1 || plan.Unchanged[0].Action != "deny" {
			t.Errorf("unchanged = %+v, want the deny rule", plan.Unchanged)
		}
		if len(plan.ToRemove) != 1 || plan.ToRemove[0].Action != "allow" {
			t.Errorf("to_remove = %+v, want the excess allow rule", plan.ToRemove)
		}
	})

	t.Run("excess proposed rules are reported as adds", func(t *testing.T) {
		cur := []intent.Policy{{Name: "x1", From: "iot", To: "wan", Action: "deny"}}
		prop := []intent.Policy{
			{Name: "x1", From: "iot", To: "wan", Action: "deny"},
			{Name: "x2", From: "iot", To: "wan", Action: "deny"},
		}
		plan := diffPolicies(cur, prop, nil)
		if len(plan.Unchanged) != 1 || len(plan.ToAdd) != 1 || plan.ToAdd[0].Action != "deny" {
			t.Errorf("plan = %+v, want 1 unchanged + 1 add", plan)
		}
	})

	t.Run("policyWithAction falls back when action absent", func(t *testing.T) {
		policies := []intent.Policy{{Name: "only", From: "a", To: "b", Action: "deny"}}
		got := policyWithAction(policies, "allow")
		if got.Name != "only" {
			t.Errorf("policyWithAction = %+v, want fallback to first policy", got)
		}
	})
}

// omadaApplyServer serves a mutable ACL rule list plus networks for
// ApplyACL tests. Writes on unexpected paths fail the test.
func omadaApplyServer(t *testing.T, initialRules string) *httptest.Server {
	t.Helper()
	state := initialRules
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case r.URL.Path == "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case r.URL.Path == "/openapi/v1/abc123/sites/s1/lan-networks":
			writeOmadaEnvelope(w, 0, `{"totalRows":3,"data":[
				{"id":"n1","name":"Trusted","gatewaySubnet":"10.0.10.1/24"},
				{"id":"n2","name":"IoT","gatewaySubnet":"10.0.20.1/24"},
				{"id":"n3","name":"Guest","gatewaySubnet":"10.0.30.1/24"}]}`)
		// Reads and writes use the per-scope Open API paths (BDD §4);
		// creates return no payload, so the post-create refetch serves
		// the updated list.
		case r.URL.Path == "/openapi/v1/abc123/sites/s1/acls/osw-acls" && r.Method == http.MethodPost:
			writeOmadaEnvelope(w, 0, "null")
			state = `{"totalRows":1,"data":[{"id":"a9","description":"block-iot","status":true,"policy":0,"protocols":[256],"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1"],"index":4}]}`
		case strings.HasPrefix(r.URL.Path, "/openapi/v1/abc123/sites/s1/acls/osw-acls/") && r.Method == http.MethodPut:
			writeOmadaEnvelope(w, 0, "null")
			state = `{"totalRows":1,"data":[{"id":"a1","description":"block-iot","status":true,"policy":0,"protocols":[256],"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1"],"index":4}]}`
		case r.URL.Path == "/openapi/v1/abc123/sites/s1/acls/osg-acls":
			writeOmadaEnvelope(w, 0, `{"totalRows":0,"data":[]}`)
		case r.URL.Path == "/openapi/v1/abc123/sites/s1/acls/osw-acls":
			writeOmadaEnvelope(w, 0, state)
		default:
			http.NotFound(w, r)
		}
	})
	return ts
}

// cannedPostAudit returns a PostAudit seam that pins the N-to-M post-audit
// spec: every endpoint declared exactly once (sources first), one isolation
// assertion per source checked against the full comma-joined destination set.
// It then returns a pass finding per assertion.
func cannedPostAudit(t *testing.T, wantFrom, wantTo []string, wantExpect string) func(ctx context.Context, spec *intent.Spec) (*models.AuditReport, error) {
	t.Helper()
	// Resolved CIDR/gateway per endpoint, matching omadaApplyServer networks.
	cidr := map[string]struct{ cidr, gw string }{
		"trusted": {"10.0.10.0/24", "10.0.10.1"},
		"iot":     {"10.0.20.0/24", "10.0.20.1"},
		"guest":   {"10.0.30.0/24", "10.0.30.1"},
	}
	// Expected network order: sources first, then destinations, deduped.
	wantNets := []string{}
	seen := map[string]bool{}
	for _, n := range append(append([]string{}, wantFrom...), wantTo...) {
		key := strings.ToLower(n)
		if !seen[key] {
			seen[key] = true
			wantNets = append(wantNets, n)
		}
	}
	dest := strings.Join(wantTo, ",")
	return func(ctx context.Context, spec *intent.Spec) (*models.AuditReport, error) {
		if len(spec.Networks) != len(wantNets) {
			got := make([]string, 0, len(spec.Networks))
			for _, n := range spec.Networks {
				got = append(got, n.Name)
			}
			t.Errorf("post-audit spec has networks %v, want %v", got, wantNets)
		}
		for i, n := range spec.Networks {
			want := wantNets[i]
			c := cidr[strings.ToLower(want)]
			if !strings.EqualFold(n.Name, want) || n.CIDR != c.cidr || n.Gateway != c.gw {
				t.Errorf("post-audit network[%d] = %+v, want %s %s gw %s", i, n, want, c.cidr, c.gw)
			}
		}
		if len(spec.Assertions) != len(wantFrom) {
			t.Fatalf("post-audit assertions = %d, want %d", len(spec.Assertions), len(wantFrom))
		}
		findings := make([]models.CheckResult, 0, len(wantFrom))
		for i, a := range spec.Assertions {
			if a.Type != "isolation" || a.From != wantFrom[i] || a.To != dest || a.Expect != wantExpect {
				t.Errorf("post-audit assertion[%d] = %+v, want isolation %s -> %s expect %s", i, a, wantFrom[i], dest, wantExpect)
			}
			findings = append(findings, models.CheckResult{
				Tool: "system", CheckType: "isolation", Runner: "local",
				Target: wantFrom[i] + " -> " + dest, Status: models.StatusPass,
				Summary: "isolation confirmed",
			})
		}
		return &models.AuditReport{Audit: "post-mutation", Status: models.StatusPass, Findings: findings}, nil
	}
}

func TestOmadaServiceApplyACL(t *testing.T) {
	t.Run("real apply runs post-audit", func(t *testing.T) {
		ts := omadaApplyServer(t, `{"totalRows":0,"data":[]}`)
		svc := NewOmadaService()
		svc.PostAudit = cannedPostAudit(t, []string{"iot"}, []string{"trusted"}, "deny")
		res, err := svc.ApplyACL(context.Background(), OmadaOptions{
			Host: ts.URL, ClientID: "admin", ClientSecret: "pw", SkipTLSVerify: true,
		}, OmadaACLApplyRequest{From: []string{"iot"}, To: []string{"trusted"}, Action: "deny", PostAudit: true})
		if err != nil {
			t.Fatalf("ApplyACL: %v", err)
		}
		if res.DryRun || res.Outcome != "created" || res.RuleID != "a9" {
			t.Errorf("result = %+v, want real created rule a9", res)
		}
		if res.PostAudit == nil || res.PostAudit.Status != string(models.StatusPass) {
			t.Fatalf("post_audit = %+v, want pass finding", res.PostAudit)
		}
		if len(res.PostAudit.Findings) != 1 || res.PostAudit.Findings[0].CheckType != "isolation" {
			t.Errorf("post_audit findings = %+v, want one isolation check", res.PostAudit.Findings)
		}
		// Result surfaces the resolved endpoint set in request order.
		if !sliceEqStr(res.FromCIDRs, []string{"10.0.20.0/24"}) || !sliceEqStr(res.ToCIDRs, []string{"10.0.10.0/24"}) {
			t.Errorf("cidrs = from %v to %v", res.FromCIDRs, res.ToCIDRs)
		}
		if res.Scope != "switch" || res.RuleName != "iot-trusted-deny" {
			t.Errorf("scope/rule = %q %q, want switch iot-trusted-deny", res.Scope, res.RuleName)
		}
	})

	t.Run("one-to-many apply runs per-source post-audit", func(t *testing.T) {
		ts := omadaApplyServer(t, `{"totalRows":0,"data":[]}`)
		svc := NewOmadaService()
		svc.PostAudit = cannedPostAudit(t, []string{"iot"}, []string{"trusted", "guest"}, "deny")
		res, err := svc.ApplyACL(context.Background(), OmadaOptions{
			Host: ts.URL, ClientID: "admin", ClientSecret: "pw", SkipTLSVerify: true,
		}, OmadaACLApplyRequest{From: []string{"iot"}, To: []string{"trusted", "guest"}, Action: "deny", PostAudit: true})
		if err != nil {
			t.Fatalf("ApplyACL: %v", err)
		}
		if res.Outcome != "created" || res.PostAudit == nil || res.PostAudit.Status != string(models.StatusPass) {
			t.Fatalf("post_audit = %+v, want pass", res)
		}
		// One isolation finding per source, each pinging the full destination set.
		if len(res.PostAudit.Findings) != 1 {
			t.Fatalf("post_audit findings = %d, want 1 (one source)", len(res.PostAudit.Findings))
		}
		if !sliceEqStr(res.ToCIDRs, []string{"10.0.10.0/24", "10.0.30.0/24"}) {
			t.Errorf("to_cidrs = %v, want trusted then guest in request order", res.ToCIDRs)
		}
	})

	t.Run("many-to-many apply emits one assertion per source", func(t *testing.T) {
		ts := omadaApplyServer(t, `{"totalRows":0,"data":[]}`)
		svc := NewOmadaService()
		svc.PostAudit = cannedPostAudit(t, []string{"iot", "guest"}, []string{"trusted"}, "deny")
		res, err := svc.ApplyACL(context.Background(), OmadaOptions{
			Host: ts.URL, ClientID: "admin", ClientSecret: "pw", SkipTLSVerify: true,
		}, OmadaACLApplyRequest{From: []string{"iot", "guest"}, To: []string{"trusted"}, Action: "deny", PostAudit: true})
		if err != nil {
			t.Fatalf("ApplyACL: %v", err)
		}
		if res.PostAudit == nil || len(res.PostAudit.Findings) != 2 {
			t.Fatalf("post_audit = %+v, want 2 findings (one per source)", res.PostAudit)
		}
	})

	t.Run("dry run defaults to no mutation and no post-audit", func(t *testing.T) {
		ts := omadaApplyServer(t, `{"totalRows":0,"data":[]}`)
		svc := NewOmadaService()
		svc.PostAudit = func(ctx context.Context, spec *intent.Spec) (*models.AuditReport, error) {
			t.Error("post-audit must not run for a dry run")
			return nil, nil
		}
		res, err := svc.ApplyACL(context.Background(), OmadaOptions{
			Host: ts.URL, ClientID: "admin", ClientSecret: "pw", SkipTLSVerify: true,
		}, OmadaACLApplyRequest{From: []string{"iot"}, To: []string{"trusted"}, Action: "deny", DryRun: true})
		if err != nil {
			t.Fatalf("ApplyACL: %v", err)
		}
		if !res.DryRun || res.Outcome != "created" || res.PostAudit != nil {
			t.Errorf("result = %+v, want dry run planned create without post-audit", res)
		}
	})

	t.Run("unchanged skips post-audit", func(t *testing.T) {
		ts := omadaApplyServer(t, `{"totalRows":1,"data":[{"id":"a1","description":"block-iot","status":true,"policy":0,"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1"],"index":4}]}`)
		svc := NewOmadaService()
		svc.PostAudit = func(ctx context.Context, spec *intent.Spec) (*models.AuditReport, error) {
			t.Error("post-audit must not run when nothing changed")
			return nil, nil
		}
		res, err := svc.ApplyACL(context.Background(), OmadaOptions{
			Host: ts.URL, ClientID: "admin", ClientSecret: "pw", SkipTLSVerify: true,
		}, OmadaACLApplyRequest{From: []string{"iot"}, To: []string{"trusted"}, Action: "deny", PostAudit: true})
		if err != nil {
			t.Fatalf("ApplyACL: %v", err)
		}
		if res.Outcome != "unchanged" || res.PostAudit != nil {
			t.Errorf("result = %+v, want unchanged without post-audit", res)
		}
	})

	t.Run("post-audit opt-out", func(t *testing.T) {
		ts := omadaApplyServer(t, `{"totalRows":0,"data":[]}`)
		svc := NewOmadaService()
		svc.PostAudit = func(ctx context.Context, spec *intent.Spec) (*models.AuditReport, error) {
			t.Error("post-audit must not run when disabled")
			return nil, nil
		}
		res, err := svc.ApplyACL(context.Background(), OmadaOptions{
			Host: ts.URL, ClientID: "admin", ClientSecret: "pw", SkipTLSVerify: true,
		}, OmadaACLApplyRequest{From: []string{"iot"}, To: []string{"trusted"}, Action: "deny", PostAudit: false})
		if err != nil {
			t.Fatalf("ApplyACL: %v", err)
		}
		if res.Outcome != "created" || res.PostAudit != nil {
			t.Errorf("result = %+v, want created without post-audit", res)
		}
	})

	t.Run("post-audit failure is reported, not fatal", func(t *testing.T) {
		ts := omadaApplyServer(t, `{"totalRows":0,"data":[]}`)
		svc := NewOmadaService()
		svc.PostAudit = func(ctx context.Context, spec *intent.Spec) (*models.AuditReport, error) {
			return nil, errors.New("engine exploded")
		}
		res, err := svc.ApplyACL(context.Background(), OmadaOptions{
			Host: ts.URL, ClientID: "admin", ClientSecret: "pw", SkipTLSVerify: true,
		}, OmadaACLApplyRequest{From: []string{"iot"}, To: []string{"trusted"}, Action: "deny", PostAudit: true})
		if err != nil {
			t.Fatalf("ApplyACL: %v", err)
		}
		if res.Outcome != "created" {
			t.Errorf("outcome = %q, want created", res.Outcome)
		}
		if res.PostAudit == nil || res.PostAudit.Status != "error" || !strings.Contains(res.PostAudit.Summary, "engine exploded") {
			t.Errorf("post_audit = %+v, want error summary with engine message", res.PostAudit)
		}
	})

	t.Run("invalid request is rejected before any controller request", func(t *testing.T) {
		svc := &OmadaService{NewClient: func(ctx context.Context, host string, skipTLSVerify bool, caCertPath string) (*omadabackend.Client, error) {
			t.Error("NewClient called; request must be validated first")
			return nil, errors.New("unexpected client")
		}}
		_, err := svc.ApplyACL(context.Background(), OmadaOptions{Host: "https://omada.local"},
			OmadaACLApplyRequest{From: []string{"a"}, To: []string{"b"}, Action: "drop"})
		if err == nil || !strings.Contains(err.Error(), "action") {
			t.Fatalf("ApplyACL error = %v, want action validation failure", err)
		}
	})
}

// sliceEqStr reports whether two string slices are equal element by element.
func sliceEqStr(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// nonMutatingProvider is a registry stand-in that lacks the ACLApplier
// surface, to verify the clear-error safety rail.
type nonMutatingProvider struct{}

func (nonMutatingProvider) Name() string           { return "omada" }
func (nonMutatingProvider) Capabilities() []string { return []string{"info"} }
func (nonMutatingProvider) Info(context.Context, providers.ImportOptions) (*providers.ProviderInfo, error) {
	return nil, nil
}
func (nonMutatingProvider) ImportSpec(context.Context, providers.ImportOptions) (*providers.ImportResult, error) {
	return nil, nil
}
func (nonMutatingProvider) Check(context.Context, providers.ImportOptions) (*providers.AuditResult, error) {
	return nil, nil
}
func (nonMutatingProvider) CheckACL(context.Context, providers.ACLCheckRequest, providers.ImportOptions) (*models.CheckResult, error) {
	return nil, nil
}

func TestOmadaServiceApplyACL_ProviderLacksMutation(t *testing.T) {
	providers.Reset()
	t.Cleanup(func() {
		providers.Reset()
		_ = providers.Register(&omadaprovider.OmadaProvider{})
	})
	if err := providers.Register(nonMutatingProvider{}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	svc := NewOmadaService()
	_, err := svc.ApplyACL(context.Background(), OmadaOptions{Host: "https://omada.local"},
		OmadaACLApplyRequest{From: []string{"a"}, To: []string{"b"}, Action: "deny"})
	if err == nil || !strings.Contains(err.Error(), "does not implement ACL mutation") {
		t.Fatalf("ApplyACL error = %v, want missing-mutation capability error", err)
	}
}

// --- port-profile (uplink / switch ports / lan profiles / plan / apply) ---

// omadaPortState is the mutable controller state for port-profile tests:
// the site's LAN profiles plus each port's bound profileId.
type omadaPortState struct {
	Profiles     []omadabackend.LanProfile
	PortProfiles map[int]string
	NextID       int
}

// omadaPortOpts is the standard (synthetic) OmadaOptions for port-profile
// tests.
func omadaPortOpts(host string) OmadaOptions {
	return OmadaOptions{Host: host, ClientID: "a", ClientSecret: "b", SkipTLSVerify: true}
}

// omadaPortNets is the fixture site's declared LAN networks.
const omadaPortNets = `[
	{"id":"n1","name":"trusted","purpose":"lan","vlan":1,"gatewaySubnet":"10.0.10.1/24","deviceMac":"aa:bb:cc:dd:ee:00"},
	{"id":"n2","name":"gaming","purpose":"lan","vlan":30,"gatewaySubnet":"10.0.10.1/24","deviceMac":"aa:bb:cc:dd:ee:00"},
	{"id":"n3","name":"media","purpose":"lan","vlan":50,"gatewaySubnet":"10.0.10.1/24","deviceMac":"aa:bb:cc:dd:ee:00"},
	{"id":"n4","name":"Personal","purpose":"lan","vlan":60,"gatewaySubnet":"10.0.10.1/24","deviceMac":"aa:bb:cc:dd:ee:00"}]`

// omadaPortBaseHandler serves the port-profile endpoints against st; the
// uplink-info, ports-overview, lan-profiles (GET/POST), and per-port
// profile-PUT paths are stateful so plan/apply tests observe real before/
// after changes.
func omadaPortBaseHandler(t *testing.T, st *omadaPortState) http.HandlerFunc {
	t.Helper()
	const swBase = "/openapi/v1/abc123/sites/s1/switches/"
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if r.Method == http.MethodPut && strings.HasPrefix(path, swBase) {
			handleProfilePut(t, w, r, st, swBase)
			return
		}
		switch {
		case path == "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case path == "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case path == "/openapi/v1/abc123/sites/s1/lan-networks":
			writeOmadaEnvelope(w, 0, `{"totalRows":4,"data":`+omadaPortNets+`}`)
		case path == "/openapi/v1/abc123/sites/s1/devices/uplink-info" && r.Method == http.MethodPost:
			var body struct {
				MACs []string `json:"deviceMacs"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("uplink-info body decode: %v", err)
			}
			// The client forwards MACs as given; compare normalized so the
			// assertion holds for any casing/separators.
			if omadabackend.NormalizeMAC(body.MACs[0]) != omadabackend.NormalizeMAC("aa:bb:cc:dd:ee:01") {
				t.Errorf("uplink-info deviceMacs = %v, want the queried MAC passed through", body.MACs)
			}
			writeOmadaEnvelope(w, 0, `[{"mac":"aa:bb:cc:dd:ee:01","uplinkDeviceMac":"bb:11:22:33:44:55","uplinkDeviceName":"SW-CORE","uplinkDevicePort":"8","linkSpeed":3,"duplex":2}]`)
		case path == "/openapi/v1/abc123/sites/s1/switches/ports/overview":
			writePortOverview(w, st)
		case path == "/openapi/v1/abc123/sites/s1/lan-profiles":
			switch r.Method {
			case http.MethodGet:
				writeOmadaEnvelope(w, 0, `{"totalRows":`+strconv.Itoa(len(st.Profiles))+`,"data":`+string(mustMarshalJSON(st.Profiles))+`}`)
			case http.MethodPost:
				var p omadabackend.LanProfile
				if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
					t.Errorf("lan-profiles create decode: %v", err)
				}
				st.NextID++
				id := fmt.Sprintf("P%d", 100+st.NextID)
				p.ID = id
				st.Profiles = append(st.Profiles, p)
				writeOmadaEnvelope(w, 0, `{"id":"`+id+`"}`)
			}
		default:
			t.Errorf("unexpected %s %s", r.Method, path)
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

// writePortOverview serves the fixture ports-overview page: ports 1, 9, and
// 10 on the second switch, port 8 on the core switch. Each row's bound
// profile tracks the mutable state so an apply is visible on re-read.
func writePortOverview(w io.Writer, st *omadaPortState) {
	rows := []map[string]any{
		{"port": 1, "portName": "GE1", "switchMac": "aa:bb:cc:dd:ee:01", "switchName": "SW-A", "connectedStatus": 0, "disable": false, "networkMode": 1, "nativeNetworkId": "n1", "nativeBridgeVlan": 0, "networkTagsSetting": 0, "profileId": st.PortProfiles[1], "profileName": "Access-trusted", "profileOverrideEnable": false},
		{"port": 8, "portName": "GE8", "switchMac": "bb:11:22:33:44:55", "switchName": "SW-CORE", "connectedStatus": 0, "disable": false, "networkMode": 0, "nativeNetworkId": "n1", "nativeBridgeVlan": 0, "networkTagsSetting": 0, "profileId": st.PortProfiles[8], "profileName": "Access-trusted", "profileOverrideEnable": false},
		{"port": 9, "portName": "GE9", "switchMac": "aa:bb:cc:dd:ee:01", "switchName": "SW-A", "connectedStatus": 1, "disable": false, "networkMode": 0, "nativeNetworkId": "", "nativeBridgeVlan": 0, "networkTagsSetting": 0, "profileId": st.PortProfiles[9], "profileName": "media+gaming", "profileOverrideEnable": false},
		{"port": 10, "portName": "GE10", "switchMac": "aa:bb:cc:dd:ee:01", "switchName": "SW-A", "connectedStatus": 0, "disable": false, "networkMode": 1, "nativeNetworkId": "n1", "nativeBridgeVlan": 0, "networkTagsSetting": 0, "profileId": st.PortProfiles[10], "profileName": "Access-trusted", "profileOverrideEnable": false},
	}
	writeOmadaEnvelope(w, 0, `{"totalRows":`+strconv.Itoa(len(rows))+`,"data":`+string(mustMarshalJSON(rows))+`}`)
}

// handleProfilePut applies a per-port profileId PUT against the state. The
// path is {swBase}{mac}/ports/{port}/profile; the MAC is split-safe
// (controller MACs use colons or dashes, never slashes).
func handleProfilePut(t *testing.T, w http.ResponseWriter, r *http.Request, st *omadaPortState, swBase string) {
	t.Helper()
	var body struct {
		ProfileID string `json:"profileId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		t.Errorf("profile PUT decode: %v", err)
	}
	parts := strings.Split(strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, swBase), "/"), "/")
	if len(parts) != 4 || parts[1] != "ports" || parts[3] != "profile" {
		t.Errorf("profile PUT path %q: unrecognized shape", r.URL.Path)
		return
	}
	port, err := strconv.Atoi(parts[2])
	if err != nil {
		t.Errorf("profile PUT path %q: port %q: %v", r.URL.Path, parts[2], err)
		return
	}
	st.PortProfiles[port] = body.ProfileID
	writeOmadaEnvelope(w, 0, `null`)
}

// omadaPortStateFresh returns the standard fixture state: ports 1, 8, and
// 10 bound to the trusted access profile, port 9 (second switch) bound to
// the media/gaming trunk profile.
func omadaPortStateFresh() *omadaPortState {
	return &omadaPortState{
		Profiles: []omadabackend.LanProfile{
			{ID: "P1", Name: "Access-trusted", PoE: 2, NativeNetworkID: "n1", TagNetworkIDs: []string{}, UntagNetworkIDs: []string{"n1"}, Dot1x: 2, BandWidthCtrlType: 0},
			{ID: "P2", Name: "media", PoE: 2, NativeNetworkID: "n3", TagNetworkIDs: []string{}, UntagNetworkIDs: []string{"n3"}, Dot1x: 2, BandWidthCtrlType: 0},
			{ID: "P3", Name: "media+gaming", PoE: 2, NativeNetworkID: "n3", TagNetworkIDs: []string{"n1", "n2"}, UntagNetworkIDs: []string{"n3"}, Dot1x: 2, BandWidthCtrlType: 0},
		},
		PortProfiles: map[int]string{1: "P1", 8: "P1", 9: "P3", 10: "P1"},
	}
}

func mustMarshalJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func TestOmadaServiceGetUplinkInfo(t *testing.T) {
	st := omadaPortStateFresh()
	ts := omadaTestServer(t, omadaPortBaseHandler(t, st))
	rows, err := NewOmadaService().GetUplinkInfo(context.Background(), omadaPortOpts(ts.URL), []string{"aa:bb:cc:dd:ee:01"})
	if err != nil {
		t.Fatalf("GetUplinkInfo: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %+v, want 1", rows)
	}
	r := rows[0]
	if r.MAC != "aa:bb:cc:dd:ee:01" || r.UplinkDevicePort != "8" || r.UplinkDeviceName != "SW-CORE" || r.LinkSpeed != 3 || r.Duplex != 2 {
		t.Errorf("row = %+v", r)
	}
}

func TestOmadaServiceGetUplinkInfo_FetchFails(t *testing.T) {
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
	_, err := NewOmadaService().GetUplinkInfo(context.Background(), omadaPortOpts(ts.URL), []string{"aa:bb:cc:dd:ee:01"})
	if err == nil {
		t.Fatal("expected uplink-info fetch failure to propagate")
	}
}

func TestOmadaServiceListSwitchPorts(t *testing.T) {
	st := omadaPortStateFresh()
	ts := omadaTestServer(t, omadaPortBaseHandler(t, st))
	all, err := NewOmadaService().ListSwitchPorts(context.Background(), omadaPortOpts(ts.URL), "")
	if err != nil {
		t.Fatalf("ListSwitchPorts: %v", err)
	}
	if len(all) != 4 {
		t.Fatalf("all = %d rows, want 4", len(all))
	}

	filtered, err := NewOmadaService().ListSwitchPorts(context.Background(), omadaPortOpts(ts.URL), "bb:11:22:33:44:55")
	if err != nil {
		t.Fatalf("ListSwitchPorts filtered: %v", err)
	}
	if len(filtered) != 1 {
		t.Fatalf("filtered = %d rows, want 1", len(filtered))
	}
	p := filtered[0]
	if p.Port != 8 || p.NetworkMode != 0 || p.NativeNetwork != "trusted" {
		t.Errorf("port = %+v", p)
	}
	if len(p.Tagged) != 0 {
		t.Errorf("port 8 tagged = %v, want empty (profile P1)", p.Tagged)
	}

	// Port 9's row has no native on the wire: it falls back to the
	// referenced profile's native network.
	for _, p := range all {
		if p.Port == 9 && p.SwitchMAC == "aa:bb:cc:dd:ee:01" {
			if p.NativeNetwork != "media" || len(p.Tagged) != 2 || p.Tagged[0] != "trusted" || p.Tagged[1] != "gaming" {
				t.Errorf("port 9 = native %q tagged %v, want media/[trusted gaming]", p.NativeNetwork, p.Tagged)
			}
		}
	}
}

func TestOmadaServiceListSwitchPorts_FetchFails(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/openapi/v1/abc123/sites/s1/lan-networks":
			writeOmadaEnvelope(w, 0, `{"totalRows":4,"data":`+omadaPortNets+`}`)
		default:
			writeOmadaEnvelope(w, -33004, `null`)
		}
	})
	_, err := NewOmadaService().ListSwitchPorts(context.Background(), omadaPortOpts(ts.URL), "")
	if err == nil {
		t.Fatal("expected ports-overview fetch failure to propagate")
	}
}

func TestOmadaServiceListLanProfiles(t *testing.T) {
	st := omadaPortStateFresh()
	ts := omadaTestServer(t, omadaPortBaseHandler(t, st))
	profiles, err := NewOmadaService().ListLanProfiles(context.Background(), omadaPortOpts(ts.URL))
	if err != nil {
		t.Fatalf("ListLanProfiles: %v", err)
	}
	if len(profiles) != 3 {
		t.Fatalf("profiles = %d, want 3", len(profiles))
	}
	byID := map[string]OmadaLanProfile{}
	for _, p := range profiles {
		byID[p.ID] = p
	}
	p3 := byID["P3"]
	if p3.Name != "media+gaming" || p3.NativeNetwork != "media" || len(p3.TaggedNetworks) != 2 {
		t.Errorf("P3 = %+v", p3)
	}
	if p1 := byID["P1"]; p1.NativeNetwork != "trusted" || len(p1.TaggedNetworks) != 0 {
		t.Errorf("P1 = %+v", p1)
	}
}

func TestOmadaServiceListLanProfiles_FetchFails(t *testing.T) {
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
	_, err := NewOmadaService().ListLanProfiles(context.Background(), omadaPortOpts(ts.URL))
	if err == nil {
		t.Fatal("expected lan-profiles fetch failure to propagate")
	}
}

func TestOmadaServicePlanPort(t *testing.T) {
	st := omadaPortStateFresh()
	ts := omadaTestServer(t, omadaPortBaseHandler(t, st))
	svc := NewOmadaService()
	ctx := context.Background()
	coreMAC := "bb:11:22:33:44:55"

	unchanged, err := svc.PlanPort(ctx, omadaPortOpts(ts.URL), OmadaPortProfileRequest{SwitchMAC: coreMAC, Port: 8, Native: "trusted"})
	if err != nil {
		t.Fatalf("PlanPort unchanged: %v", err)
	}
	if unchanged.Outcome != "unchanged" || unchanged.ProfileID != "P1" || unchanged.Site != "HQ" {
		t.Errorf("unchanged = outcome %q profile %q site %q", unchanged.Outcome, unchanged.ProfileID, unchanged.Site)
	}
	if unchanged.Current == nil || unchanged.Current.ProfileID != "P1" || unchanged.CurrentProfile == nil || unchanged.CurrentProfile.Name != "Access-trusted" {
		t.Errorf("unchanged current = %+v / %+v", unchanged.Current, unchanged.CurrentProfile)
	}

	rebind, err := svc.PlanPort(ctx, omadaPortOpts(ts.URL), OmadaPortProfileRequest{
		SwitchMAC: "AA:BB:CC:DD:EE:01", Port: 10, Native: "media", Tagged: []string{"trusted", "gaming"},
	})
	if err != nil {
		t.Fatalf("PlanPort rebind: %v", err)
	}
	if rebind.Outcome != "rebind" || rebind.ProfileID != "P3" || rebind.ProfileName != "media+gaming" {
		t.Errorf("rebind = outcome %q profile %q name %q", rebind.Outcome, rebind.ProfileID, rebind.ProfileName)
	}
	if rebind.CurrentProfile == nil || rebind.CurrentProfile.ID != "P1" {
		t.Errorf("rebind current profile = %+v", rebind.CurrentProfile)
	}

	create, err := svc.PlanPort(ctx, omadaPortOpts(ts.URL), OmadaPortProfileRequest{
		SwitchMAC: "AA:BB:CC:DD:EE:01", Port: 1, Native: "Personal", Tagged: []string{"media"},
	})
	if err != nil {
		t.Fatalf("PlanPort create: %v", err)
	}
	if create.Outcome != "create" || create.ProfileCreate != true || create.ProfileName != "Personal+trunk(1)" {
		t.Errorf("create = outcome %q create %v name %q", create.Outcome, create.ProfileCreate, create.ProfileName)
	}
}

func TestOmadaServicePlanPort_Errors(t *testing.T) {
	st := omadaPortStateFresh()
	ts := omadaTestServer(t, omadaPortBaseHandler(t, st))
	svc := NewOmadaService()
	ctx := context.Background()
	opts := omadaPortOpts(ts.URL)
	coreMAC := "bb:11:22:33:44:55"

	_, err := svc.PlanPort(ctx, opts, OmadaPortProfileRequest{SwitchMAC: coreMAC, Port: 9, Native: "trusted"})
	if err == nil || !strings.Contains(err.Error(), "port 9 not found on switch") {
		t.Errorf("missing port: err = %v", err)
	}

	_, err = svc.PlanPort(ctx, opts, OmadaPortProfileRequest{SwitchMAC: coreMAC, Port: 8, Native: "Nope"})
	if err == nil || !strings.Contains(err.Error(), `network "Nope" is not a declared LAN network`) {
		t.Errorf("unknown network: err = %v", err)
	}

	_, err = svc.PlanPort(ctx, opts, OmadaPortProfileRequest{
		SwitchMAC: coreMAC, Port: 8, Native: "media", Tagged: []string{"media"},
	})
	if err == nil || !strings.Contains(err.Error(), "must not also appear in the tagged list") {
		t.Errorf("overlap: err = %v", err)
	}
}

func TestOmadaServiceApplyPortProfile_Outcomes(t *testing.T) {
	st := omadaPortStateFresh()
	ts := omadaTestServer(t, omadaPortBaseHandler(t, st))
	svc := NewOmadaService()
	ctx := context.Background()
	opts := omadaPortOpts(ts.URL)
	coreMAC := "bb:11:22:33:44:55"

	// Idempotent: the bound profile already matches → unchanged, no writes.
	beforeProfiles := len(st.Profiles)
	res, err := svc.ApplyPortProfile(ctx, opts, OmadaPortProfileRequest{SwitchMAC: coreMAC, Port: 8, Native: "trusted"}, false)
	if err != nil {
		t.Fatalf("apply unchanged: %v", err)
	}
	if res.Outcome != "unchanged" || res.DryRun || len(st.PortProfiles) != 4 || len(st.Profiles) != beforeProfiles {
		t.Errorf("unchanged = %+v, mutations: portProfile=%v profiles=%d", res, st.PortProfiles, len(st.Profiles))
	}
	if res.Before == "" || res.After == "" || res.Before != res.After {
		t.Errorf("unchanged evidence = before %q after %q", res.Before, res.After)
	}

	// Rebind: port 10 is bound to the access profile; the matching member
	// profile P3 exists → bound without a create.
	res, err = svc.ApplyPortProfile(ctx, opts, OmadaPortProfileRequest{
		SwitchMAC: "AA:BB:CC:DD:EE:01", Port: 10, Native: "media", Tagged: []string{"trusted", "gaming"},
	}, false)
	if err != nil {
		t.Fatalf("apply rebind: %v", err)
	}
	if res.Outcome != "bound" || res.ProfileID != "P3" || res.ProfileCreate {
		t.Errorf("rebind = %+v", res)
	}
	if st.PortProfiles[10] != "P3" {
		t.Errorf("port 10 profile = %q, want P3", st.PortProfiles[10])
	}
	if !strings.Contains(res.After, `"P3"`) || !strings.Contains(res.Before, `"P1"`) {
		t.Errorf("evidence before=%s after=%s", res.Before, res.After)
	}

	// Create: no member-matching profile → create with the derived name and
	// safe defaults, then bind.
	res, err = svc.ApplyPortProfile(ctx, opts, OmadaPortProfileRequest{
		SwitchMAC: coreMAC, Port: 8, Native: "Personal", Tagged: []string{"media"},
	}, false)
	if err != nil {
		t.Fatalf("apply create: %v", err)
	}
	if res.Outcome != "created_and_bound" || res.ProfileID == "" || res.ProfileName != "Personal+trunk(1)" || !res.ProfileCreate {
		t.Fatalf("create = %+v", res)
	}
	created := findTestProfile(st.Profiles, res.ProfileID)
	if created == nil {
		t.Fatalf("created profile %q not in state", res.ProfileID)
	}
	if created.NativeNetworkID != "n4" || len(created.TagNetworkIDs) != 1 || created.TagNetworkIDs[0] != "n3" ||
		len(created.UntagNetworkIDs) != 1 || created.UntagNetworkIDs[0] != "n4" {
		t.Errorf("created membership = %+v", created)
	}
	if created.PoE != 2 || created.Dot1x != 2 || created.BandWidthCtrlType != 0 ||
		created.PortIsolationEnable || created.LLDPMEDEnable || created.SpanningTreeEnable || created.LoopbackDetectEnable {
		t.Errorf("created defaults = %+v, want PoE=2 Dot1x=2 BW=0 bools false", created)
	}
	if st.PortProfiles[8] != res.ProfileID {
		t.Errorf("port 8 profile = %q, want %q", st.PortProfiles[8], res.ProfileID)
	}
	if !strings.Contains(res.Before, `"P1"`) || !strings.Contains(res.After, res.ProfileID) {
		t.Errorf("evidence before=%s after=%s", res.Before, res.After)
	}

	// Re-apply the same request: the newly bound profile now matches →
	// unchanged (idempotent).
	res, err = svc.ApplyPortProfile(ctx, opts, OmadaPortProfileRequest{
		SwitchMAC: coreMAC, Port: 8, Native: "Personal", Tagged: []string{"media"},
	}, false)
	if err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	if res.Outcome != "unchanged" || res.ProfileID != created.ID {
		t.Errorf("re-apply = outcome %q profile %q, want unchanged/%s", res.Outcome, res.ProfileID, created.ID)
	}
}

func TestOmadaServiceApplyPortProfile_DryRun(t *testing.T) {
	st := omadaPortStateFresh()
	ts := omadaTestServer(t, omadaPortBaseHandler(t, st))
	res, err := NewOmadaService().ApplyPortProfile(context.Background(), omadaPortOpts(ts.URL),
		OmadaPortProfileRequest{SwitchMAC: "bb:11:22:33:44:55", Port: 8, Native: "Personal", Tagged: []string{"media"}},
		true)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	// A dry run previews the real-apply outcome vocabulary.
	if !res.DryRun || res.Outcome != "created_and_bound" || !res.ProfileCreate || res.ProfileID != "" || res.ProfileName != "Personal+trunk(1)" {
		t.Errorf("dry run = %+v", res)
	}
	if len(st.Profiles) != 3 || st.PortProfiles[8] != "P1" {
		t.Errorf("dry run mutated state: profiles=%d port8=%q", len(st.Profiles), st.PortProfiles[8])
	}
	if res.Before == "" || res.Before != res.After {
		t.Errorf("dry run evidence = before %q after %q", res.Before, res.After)
	}
}

func TestOmadaServiceApplyPortProfile_Errors(t *testing.T) {
	st := omadaPortStateFresh()
	ts := omadaTestServer(t, omadaPortBaseHandler(t, st))
	svc := NewOmadaService()
	ctx := context.Background()
	opts := omadaPortOpts(ts.URL)

	_, err := svc.ApplyPortProfile(ctx, opts, OmadaPortProfileRequest{
		SwitchMAC: "bb:11:22:33:44:55", Port: 42, Native: "trusted",
	}, false)
	if err == nil || !strings.Contains(err.Error(), "port 42 not found on switch") {
		t.Errorf("missing port: err = %v", err)
	}

	_, err = svc.ApplyPortProfile(ctx, opts, OmadaPortProfileRequest{
		SwitchMAC: "bb:11:22:33:44:55", Port: 8, Native: "Nope",
	}, false)
	if err == nil || !strings.Contains(err.Error(), `network "Nope" is not a declared LAN network`) {
		t.Errorf("unknown network: err = %v", err)
	}
	if len(st.Profiles) != 3 {
		t.Errorf("failed apply created profiles: %d", len(st.Profiles))
	}

	ts2 := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		default:
			writeOmadaEnvelope(w, -33004, `null`)
		}
	})
	_, err = svc.ApplyPortProfile(ctx, omadaPortOpts(ts2.URL), OmadaPortProfileRequest{
		SwitchMAC: "bb:11:22:33:44:55", Port: 8, Native: "trusted",
	}, false)
	if err == nil {
		t.Error("expected fetch failure to propagate from apply")
	}
}

func TestResolveNetworkIDList(t *testing.T) {
	nets := []omadabackend.Network{
		{ID: "n1", Name: "trusted"},
		{ID: "n2", Name: "Guest"},
		{ID: "n3", Name: "guest"},
	}

	if id, err := resolveNetworkIDList(nets, []string{"TRUSTED"}); err != nil || len(id) != 1 || id[0] != "n1" {
		t.Errorf("case-insensitive resolve = %v, %v", id, err)
	}
	if id, err := resolveNetworkIDList(nets, []string{"n2"}); err != nil || len(id) != 1 || id[0] != "n2" {
		t.Errorf("raw id passthrough = %v, %v", id, err)
	}

	// A shared display name fails closed with the candidate IDs, never a
	// first-match coin flip.
	_, err := resolveNetworkIDList(nets, []string{"guest"})
	if err == nil || !strings.Contains(err.Error(), `network name "guest" is ambiguous`) ||
		!strings.Contains(err.Error(), "n2") || !strings.Contains(err.Error(), "n3") {
		t.Errorf("duplicate name: err = %v", err)
	}

	// A raw ID is never ambiguous, even when its network shares a name.
	if id, err := resolveNetworkIDList(nets, []string{"n3"}); err != nil || id[0] != "n3" {
		t.Errorf("raw id of ambiguous-named network = %v, %v", id, err)
	}
}

func TestPlanPort_AmbiguousNativeName(t *testing.T) {
	st := omadaPortStateFresh()
	// Two declared networks share the display name "guest".
	nets := strings.Replace(omadaPortNets, `"name":"Personal"`, `"name":"guest"`, 1)
	nets = strings.Replace(nets, `"name":"trusted"`, `"name":"guest"`, 1)
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/openapi/v1/abc123/sites/s1/lan-networks":
			writeOmadaEnvelope(w, 0, `{"totalRows":4,"data":`+nets+`}`)
		case "/openapi/v1/abc123/sites/s1/switches/ports/overview":
			writePortOverview(w, st)
		case "/openapi/v1/abc123/sites/s1/lan-profiles":
			writeOmadaEnvelope(w, 0, `{"totalRows":`+strconv.Itoa(len(st.Profiles))+`,"data":`+string(mustMarshalJSON(st.Profiles))+`}`)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	_, err := NewOmadaService().PlanPort(context.Background(), omadaPortOpts(ts.URL),
		OmadaPortProfileRequest{SwitchMAC: "bb:11:22:33:44:55", Port: 8, Native: "guest"})
	if err == nil || !strings.Contains(err.Error(), `network name "guest" is ambiguous`) {
		t.Errorf("plan with duplicate native name: err = %v", err)
	}
}

// findTestProfile returns one stored profile by ID, or nil.
func findTestProfile(profiles []omadabackend.LanProfile, id string) *omadabackend.LanProfile {
	for i := range profiles {
		if profiles[i].ID == id {
			return &profiles[i]
		}
	}
	return nil
}
