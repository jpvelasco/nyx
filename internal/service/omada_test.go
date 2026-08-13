package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

const omadaTestInfo = `{"errorCode":0,"msg":"","result":{"controllerVer":"6.4.5.1","apiVer":"2.0","omadacId":"abc123","configured":true}}`

// omadaTestServer spins up a TLS test server that answers /api/info like a
// real Omada controller; everything else is delegated to h.
func omadaTestServer(t *testing.T, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/info" {
			w.Write([]byte(omadaTestInfo))
			return
		}
		h(w, r)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func writeOmadaEnvelope(w http.ResponseWriter, errorCode int, result string) {
	w.Write([]byte(`{"errorCode":` + strconv.Itoa(errorCode) + `,"msg":"","result":` + result + `}`))
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
	var loggedOut bool
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/abc123/api/v2/login":
			if r.Method != http.MethodPost {
				t.Errorf("login method = %s, want POST", r.Method)
			}
			writeOmadaEnvelope(w, 0, `{"token":"tok"}`)
		case "/abc123/api/v2/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/abc123/api/v2/sites/s1/setting/lan/networks":
			writeOmadaEnvelope(w, 0, `{"totalRows":2,"data":[
				{"id":"n1","name":"Trusted","purpose":"lan","vlan":10,"gatewaySubnet":"10.0.10.1/24","isolation":false,"dhcpEnabled":true},
				{"id":"n2","name":"IoT","purpose":"lan","vlan":20,"gatewaySubnet":"10.0.20.1/24","isolation":true,"dhcpEnabled":false}]}`)
		case "/abc123/api/v2/logout":
			loggedOut = true
			writeOmadaEnvelope(w, 0, "null")
		default:
			http.NotFound(w, r)
		}
	})

	nets, err := NewOmadaService().ListNetworks(context.Background(), OmadaOptions{
		Host: ts.URL, Username: "admin", Password: "pw", SkipTLSVerify: true,
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
	if !loggedOut {
		t.Error("expected logout after network fetch")
	}
}

func TestOmadaServiceListNetworks_SiteSelection(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/abc123/api/v2/login":
			writeOmadaEnvelope(w, 0, `{"token":"tok"}`)
		case "/abc123/api/v2/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":2,"data":[
				{"id":"s1","name":"HQ"},
				{"id":"s2","name":"Branch"}]}`)
		case "/abc123/api/v2/sites/s1/setting/lan/networks":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"n-hq","name":"HQ Net"}]}`)
		case "/abc123/api/v2/sites/s2/setting/lan/networks":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"n-branch","name":"Branch Net"}]}`)
		case "/abc123/api/v2/logout":
			writeOmadaEnvelope(w, 0, "null")
		default:
			http.NotFound(w, r)
		}
	})

	t.Run("defaults to first site", func(t *testing.T) {
		nets, err := NewOmadaService().ListNetworks(context.Background(), OmadaOptions{
			Host: ts.URL, Username: "admin", Password: "pw", SkipTLSVerify: true,
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
			Host: ts.URL, Username: "admin", Password: "pw", Site: "Branch", SkipTLSVerify: true,
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
			Host: ts.URL, Username: "admin", Password: "pw", Site: "Nope", SkipTLSVerify: true,
		})
		if err == nil || !strings.Contains(err.Error(), "not found; available sites: HQ, Branch") {
			t.Fatalf("ListNetworks error = %v, want site not found listing sites", err)
		}
	})
}

func TestOmadaService_SessionFailures(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/abc123/api/v2/login":
			writeOmadaEnvelope(w, -30109, "bad creds")
		default:
			http.NotFound(w, r)
		}
	})
	authOpts := OmadaOptions{Host: ts.URL, Username: "admin", Password: "nope", SkipTLSVerify: true}
	connectOpts := OmadaOptions{Host: "https://127.0.0.1:1", Username: "admin", Password: "pw", SkipTLSVerify: true}
	cases := []struct {
		name string
		opts OmadaOptions
		want string
		call func(opts OmadaOptions) error
	}{
		{"networks/login-fail", authOpts, "login failed", func(opts OmadaOptions) error {
			_, err := NewOmadaService().ListNetworks(context.Background(), opts)
			return err
		}},
		{"acls/login-fail", authOpts, "login failed", func(opts OmadaOptions) error {
			_, err := NewOmadaService().ListACLs(context.Background(), opts)
			return err
		}},
		{"clients/login-fail", authOpts, "login failed", func(opts OmadaOptions) error {
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
		case "/abc123/api/v2/login":
			writeOmadaEnvelope(w, 0, `{"token":"tok"}`)
		default:
			http.NotFound(w, r)
		}
	})

	_, err := NewOmadaService().ListNetworks(context.Background(), OmadaOptions{
		Host: ts.URL, Username: "admin", Password: "pw", SkipTLSVerify: true,
	})
	if err == nil || !strings.Contains(err.Error(), "fetching sites") {
		t.Fatalf("ListNetworks error = %v, want sites fetch failure", err)
	}
}

func TestOmadaServiceListNetworks_FetchFails(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/abc123/api/v2/login":
			writeOmadaEnvelope(w, 0, `{"token":"tok"}`)
		case "/abc123/api/v2/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		default:
			http.NotFound(w, r)
		}
	})

	_, err := NewOmadaService().ListNetworks(context.Background(), OmadaOptions{
		Host: ts.URL, Username: "admin", Password: "pw", SkipTLSVerify: true,
	})
	if err == nil || !strings.Contains(err.Error(), "fetching networks") {
		t.Fatalf("ListNetworks error = %v, want networks fetch failure", err)
	}
}

func TestOmadaServiceListACLs(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/abc123/api/v2/login":
			writeOmadaEnvelope(w, 0, `{"token":"tok"}`)
		case "/abc123/api/v2/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/abc123/api/v2/sites/s1/setting/firewall/acl":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"a1","name":"Block IoT","status":true,"policy":"drop","protocols":"all","srcType":"network","srcName":"IoT","dstType":"network","dstName":"Trusted","index":1}]}`)
		case "/abc123/api/v2/sites/s1/setting/firewall/gwacl":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"g1","name":"Deny Guest","status":false,"policy":"drop","protocols":"tcp","srcType":"network","srcName":"Guest","dstType":"network","dstName":"Trusted","index":5}]}`)
		case "/abc123/api/v2/logout":
			writeOmadaEnvelope(w, 0, "null")
		default:
			http.NotFound(w, r)
		}
	})

	rules, err := NewOmadaService().ListACLs(context.Background(), OmadaOptions{
		Host: ts.URL, Username: "admin", Password: "pw", SkipTLSVerify: true,
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
	if gw.Name != "Deny Guest" || gw.Enabled || gw.Protocols != "tcp" || gw.Index != 5 {
		t.Errorf("gateway rule = %+v, want disabled tcp rule index 5", gw)
	}
}

func TestOmadaServiceListACLs_GatewayFetchFails(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/abc123/api/v2/login":
			writeOmadaEnvelope(w, 0, `{"token":"tok"}`)
		case "/abc123/api/v2/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/abc123/api/v2/sites/s1/setting/firewall/acl":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"a1","name":"Block IoT"}]}`)
		default:
			http.NotFound(w, r)
		}
	})

	_, err := NewOmadaService().ListACLs(context.Background(), OmadaOptions{
		Host: ts.URL, Username: "admin", Password: "pw", SkipTLSVerify: true,
	})
	if err == nil || !strings.Contains(err.Error(), "gateway ACL") {
		t.Fatalf("ListACLs error = %v, want gateway ACL failure", err)
	}
}

func TestOmadaServiceListACLs_SwitchFetchFails(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/abc123/api/v2/login":
			writeOmadaEnvelope(w, 0, `{"token":"tok"}`)
		case "/abc123/api/v2/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		default:
			http.NotFound(w, r)
		}
	})

	_, err := NewOmadaService().ListACLs(context.Background(), OmadaOptions{
		Host: ts.URL, Username: "admin", Password: "pw", SkipTLSVerify: true,
	})
	if err == nil || !strings.Contains(err.Error(), "fetching ACL rules") {
		t.Fatalf("ListACLs error = %v, want switch ACL failure", err)
	}
}

func TestOmadaServiceListClients(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/abc123/api/v2/login":
			writeOmadaEnvelope(w, 0, `{"token":"tok"}`)
		case "/abc123/api/v2/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/abc123/api/v2/sites/s1/clients":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"mac":"aa:bb:cc:dd:ee:ff","ip":"10.0.10.5","name":"nas","hostName":"nas.local","networkName":"Trusted","ssid":"","vid":10,"wireless":false,"vendor":"Synology","deviceType":"nas","active":true,"uptime":86400}]}`)
		case "/abc123/api/v2/logout":
			writeOmadaEnvelope(w, 0, "null")
		default:
			http.NotFound(w, r)
		}
	})

	clients, err := NewOmadaService().ListClients(context.Background(), OmadaOptions{
		Host: ts.URL, Username: "admin", Password: "pw", SkipTLSVerify: true,
	})
	if err != nil {
		t.Fatalf("ListClients: %v", err)
	}
	if len(clients) != 1 {
		t.Fatalf("got %d clients, want 1", len(clients))
	}
	cl := clients[0]
	if cl.MAC != "aa:bb:cc:dd:ee:ff" || cl.IP != "10.0.10.5" || cl.Name != "nas" || cl.Hostname != "nas.local" {
		t.Errorf("client identity = %+v", cl)
	}
	if cl.NetworkName != "Trusted" || cl.VLANID != 10 || cl.Wireless || cl.Vendor != "Synology" || cl.DeviceType != "nas" || !cl.Active {
		t.Errorf("client attributes = %+v", cl)
	}
	if cl.Uptime != 86400 {
		t.Errorf("uptime = %d, want 86400", cl.Uptime)
	}
}

func TestOmadaServiceListClients_FetchFails(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/abc123/api/v2/login":
			writeOmadaEnvelope(w, 0, `{"token":"tok"}`)
		case "/abc123/api/v2/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		default:
			http.NotFound(w, r)
		}
	})

	_, err := NewOmadaService().ListClients(context.Background(), OmadaOptions{
		Host: ts.URL, Username: "admin", Password: "pw", SkipTLSVerify: true,
	})
	if err == nil || !strings.Contains(err.Error(), "fetching clients") {
		t.Fatalf("ListClients error = %v, want clients fetch failure", err)
	}
}
