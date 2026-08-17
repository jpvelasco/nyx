package opnsense

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/intent"
	providers "github.com/jpvelasco/nyx/internal/providers"
)

// TestParseAPIResponse tests parsing API response
func TestParseAPIResponse(t *testing.T) {
	jsonData := `{
		"networks": [
			{"name": "personal", "cidr": "10.0.20.0/24"}
		],
		"policies": [
			{"name": "personal-isolation", "from": "personal", "to": "gaming", "action": "deny"}
		]
	}`

	var response struct {
		Networks []struct {
			Name string `json:"name"`
			Cidr string `json:"cidr"`
		} `json:"networks"`
		Policies []struct {
			Name   string `json:"name"`
			From   string `json:"from"`
			To     string `json:"to"`
			Action string `json:"action"`
		} `json:"policies"`
	}

	if err := json.Unmarshal([]byte(jsonData), &response); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if len(response.Networks) == 0 {
		t.Error("expected at least one network")
	}

	if len(response.Policies) == 0 {
		t.Error("expected at least one policy")
	}
}

func TestProviderIdentity(t *testing.T) {
	p := &Provider{}
	if p.Name() != "opnsense" {
		t.Errorf("Name() = %q, want opnsense", p.Name())
	}
	caps := p.Capabilities()
	if len(caps) != 3 || caps[0] != "info" || caps[1] != "import" || caps[2] != "check" {
		t.Errorf("Capabilities() = %v, want [info import check]", caps)
	}
}

func TestProviderInfo(t *testing.T) {
	t.Run("missing host", func(t *testing.T) {
		p := &Provider{}
		_, err := p.Info(context.Background(), providers.ImportOptions{})
		if err == nil || !strings.Contains(err.Error(), "--host is required") {
			t.Errorf("error = %v, want --host is required", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(firmwareJSON))
		}))
		defer ts.Close()

		p := &Provider{}
		info, err := p.Info(context.Background(), providers.ImportOptions{
			Host:          ts.URL,
			SkipTLSVerify: true,
		})
		if err != nil {
			t.Fatalf("Info: %v", err)
		}
		if info.Provider != "opnsense" || info.Version != "24.1.7" {
			t.Errorf("info = %+v", info)
		}
		if info.Extra["product"] != "OPNsense" || info.Extra["arch"] != "amd64" {
			t.Errorf("extra = %v", info.Extra)
		}
	})

	t.Run("firmware fetch fails", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()

		p := &Provider{}
		_, err := p.Info(context.Background(), providers.ImportOptions{Host: ts.URL, SkipTLSVerify: true})
		if err == nil {
			t.Error("expected error for firmware fetch failure")
		}
	})
}

// opnsenseServer returns a test server serving a canned OPNsense API
// (real endpoint shapes: interfaces_info map, paged searchRule rows).
func opnsenseServer(t *testing.T, leases string) *httptest.Server {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/core/firmware/running":
			w.Write([]byte(firmwareJSON))
		case "/api/interfaces/overview/interfaces_info":
			w.Write([]byte(`{"interfaces":{
				"lan":{"description":"LAN","dhcp":false,"ipv4":"10.0.0.1/24","ipv4_gateway":"10.0.0.254"},
				"wan":{"description":"WAN","dhcp":true,"ipv4":"203.0.113.1/24","ipv4_gateway":"203.0.113.254"},
				"no-ip":{"description":"","dhcp":false,"ipv4":"","ipv4_gateway":""},
				"bad-cidr":{"description":"","dhcp":false,"ipv4":"999.1.1.1/99","ipv4_gateway":""}
			}}`))
		case "/api/firewall/filter/searchRule":
			w.Write([]byte(`{"total":5,"rows":[
				{"uuid":"u1","enabled":"1","action":"block","description":"Deny LAN to IOT","interface":["lan"],"source_net":"10.0.0.5","destination_net":"203.0.113.9"},
				{"uuid":"u2","enabled":"1","action":"reject","interface":["lan"],"source_net":"10.0.0.6","destination_net":"203.0.113.10"},
				{"uuid":"u3","enabled":"1","action":"pass","description":"allow dns","interface":["lan"],"source_net":"any","destination_net":"any"},
				{"uuid":"u4","enabled":"0","action":"block","interface":["lan"],"source_net":"10.0.0.7","destination_net":"203.0.113.11"},
				{"uuid":"u5","enabled":"1","action":"block","description":"unresolvable endpoints","interface":["lan"],"source_net":"any","destination_net":"203.0.113.9"}
			]}`))
		case "/api/dhcpd/leases":
			w.Write([]byte(leases))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestProviderImportSpec(t *testing.T) {
	t.Run("missing host", func(t *testing.T) {
		p := &Provider{}
		_, err := p.ImportSpec(context.Background(), providers.ImportOptions{})
		if err == nil || !strings.Contains(err.Error(), "--host is required") {
			t.Errorf("error = %v, want --host is required", err)
		}
	})

	t.Run("missing credentials", func(t *testing.T) {
		p := &Provider{}
		_, err := p.ImportSpec(context.Background(), providers.ImportOptions{Host: "h"})
		if err == nil || !strings.Contains(err.Error(), "--username and --password are required") {
			t.Errorf("error = %v, want credentials required", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		ts := opnsenseServer(t, `{"leases":[{"mac":"aa","ip":"10.0.0.10","hostname":"laptop"}]}`)
		p := &Provider{}
		opts := providers.ImportOptions{
			Host:          ts.URL,
			Username:      "key",
			Password:      "secret",
			SkipTLSVerify: true,
		}
		res, err := p.ImportSpec(context.Background(), opts)
		if err != nil {
			t.Fatalf("ImportSpec: %v", err)
		}
		if res.NetworkCount != 2 || res.PolicyCount != 2 || res.ClientCount != 1 {
			t.Errorf("counts = %d/%d/%d, want 2/2/1", res.NetworkCount, res.PolicyCount, res.ClientCount)
		}
		spec := res.Spec
		if spec == nil || len(spec.Networks) != 2 {
			t.Fatalf("spec = %+v, want 2 networks", spec)
		}
		if spec.Networks[0].Name != "lan" || spec.Networks[0].Zone != "clients" ||
			spec.Networks[0].Gateway != "10.0.0.254" {
			t.Errorf("network[0] = %+v", spec.Networks[0])
		}
		if spec.Networks[1].Zone != "wan" {
			t.Errorf("network[1] = %+v", spec.Networks[1])
		}
		if len(spec.Policies) != 2 {
			t.Fatalf("policies = %+v, want 2", spec.Policies)
		}
		if spec.Policies[0].Name != "deny lan to iot" || spec.Policies[0].Action != "deny" {
			t.Errorf("policy[0] = %+v", spec.Policies[0])
		}
		if len(spec.Assertions) < 5 {
			t.Errorf("assertions = %+v, want subnet_discovery+network_health per net + 2 isolation", spec.Assertions)
		}
		for _, a := range spec.Assertions {
			if a.Type == "subnet_discovery" && a.ScanMode != "polite" {
				t.Errorf("subnet_discovery %q scan_mode = %q, want %q (SYN-flood safe default)", a.Network, a.ScanMode, "polite")
			}
		}
		if len(res.Warnings) != 2 {
			t.Errorf("warnings = %v, want 2", res.Warnings)
		}
	})

	t.Run("firmware fails", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()
		p := &Provider{}
		_, err := p.ImportSpec(context.Background(), providers.ImportOptions{Host: ts.URL, Username: "k", Password: "s", SkipTLSVerify: true})
		if err == nil || !strings.Contains(err.Error(), "fetching firmware info") {
			t.Errorf("error = %v, want fetching firmware info", err)
		}
	})

	t.Run("interfaces fail", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/core/firmware/running" {
				w.Write([]byte(firmwareJSON))
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()
		p := &Provider{}
		_, err := p.ImportSpec(context.Background(), providers.ImportOptions{Host: ts.URL, Username: "k", Password: "s", SkipTLSVerify: true})
		if err == nil || !strings.Contains(err.Error(), "fetching interfaces") {
			t.Errorf("error = %v, want fetching interfaces", err)
		}
	})

	t.Run("rules fetch fails", func(t *testing.T) {
		// GetFirewallRules surfaces transport/API errors — a silent "0
		// policies" import would hide revoked keys or an unreachable API.
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/core/firmware/running":
				w.Write([]byte(firmwareJSON))
			case "/api/interfaces/overview/interfaces_info":
				w.Write([]byte(`{"interfaces":{"lan":{"ipv4":"10.0.0.1/24"}}}`))
			case "/api/firewall/filter/searchRule":
				w.WriteHeader(http.StatusInternalServerError)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer ts.Close()
		p := &Provider{}
		_, err := p.ImportSpec(context.Background(), providers.ImportOptions{Host: ts.URL, Username: "k", Password: "s", SkipTLSVerify: true})
		if err == nil || !strings.Contains(err.Error(), "fetching firewall rules") {
			t.Errorf("error = %v, want fetching firewall rules", err)
		}
	})

	t.Run("leases fail", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/core/firmware/running":
				w.Write([]byte(firmwareJSON))
			case "/api/interfaces/overview/interfaces_info":
				w.Write([]byte(`{"interfaces":{"lan":{"ipv4":"10.0.0.1/24"}}}`))
			case "/api/firewall/filter/searchRule":
				w.Write([]byte(`{"total":0,"rows":[]}`))
			case "/api/dhcpd/leases":
				w.WriteHeader(http.StatusInternalServerError)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer ts.Close()
		p := &Provider{}
		_, err := p.ImportSpec(context.Background(), providers.ImportOptions{Host: ts.URL, Username: "k", Password: "s", SkipTLSVerify: true})
		if err == nil || !strings.Contains(err.Error(), "fetching DHCP leases") {
			t.Errorf("error = %v, want fetching DHCP leases", err)
		}
	})
}

func TestProviderCheck(t *testing.T) {
	t.Run("success with empty spec", func(t *testing.T) {
		// No interfaces with IPs → no networks → no assertions → the audit
		// engine runs with an empty assertion list (hermetic, no network I/O).
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/core/firmware/running":
				w.Write([]byte(firmwareJSON))
			case "/api/interfaces/overview/interfaces_info":
				w.Write([]byte(`{"interfaces":{}}`))
			case "/api/firewall/filter/searchRule":
				w.Write([]byte(`{"total":0,"rows":[]}`))
			case "/api/dhcpd/leases":
				w.Write([]byte(`{"leases":[]}`))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer ts.Close()

		p := &Provider{}
		res, err := p.Check(context.Background(), providers.ImportOptions{
			Host: ts.URL, Username: "k", Password: "s", SkipTLSVerify: true,
		})
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if res.Report == nil {
			t.Fatal("Report is nil")
		}
		if len(res.Warnings) != 2 {
			t.Errorf("warnings = %v, want 2", res.Warnings)
		}
	})

	t.Run("import fails", func(t *testing.T) {
		p := &Provider{}
		_, err := p.Check(context.Background(), providers.ImportOptions{Host: "https://127.0.0.1:1", Username: "k", Password: "s"})
		if err == nil {
			t.Error("expected import failure to propagate")
		}
	})
}

func TestProviderCheckACL(t *testing.T) {
	p := &Provider{}
	res, err := p.CheckACL(context.Background(), providers.ACLCheckRequest{PolicyName: "x"}, providers.ImportOptions{})
	if err != nil {
		t.Fatalf("CheckACL: %v", err)
	}
	if res.Status != "error" {
		t.Errorf("status = %s, want error", res.Status)
	}
	if res.Summary != "CheckACL is not yet implemented for the OPNsense provider" {
		t.Errorf("summary = %q", res.Summary)
	}
}

func TestInferZone(t *testing.T) {
	cases := []struct {
		name, desc string
		want       string
	}{
		{"lan", "", "clients"},
		{"wan", "", "wan"},
		{"guest", "", "guest"},
		{"iot", "", "iot"},
		{"management", "", "management"},
		{"mgt", "", "management"},
		{"server", "", "servers"},
		{"srv", "", "servers"},
		{"voice", "", "voice"},
		{"voip", "", "voice"},
		{"opt1", "vlan 10", "vlan"},
		{"opt1", "", "segment"},
	}
	for _, tc := range cases {
		t.Run(tc.name+"/"+tc.desc, func(t *testing.T) {
			if got := inferZone(tc.name, tc.desc); got != tc.want {
				t.Errorf("inferZone(%q,%q) = %q, want %q", tc.name, tc.desc, got, tc.want)
			}
		})
	}
}

func TestInferZoneFromAddress(t *testing.T) {
	networks := []intent.Network{
		{Name: "lan", CIDR: "10.0.0.0/24", Zone: "clients"},
		{Name: "wan", CIDR: "203.0.113.0/24", Zone: "wan"},
		{Name: "broken", CIDR: "not-a-cidr", Zone: "broken"},
	}
	cases := []struct {
		name, address string
		want          string
	}{
		{"empty", "", ""},
		{"any", "any", ""},
		{"not an ip", "foo", ""},
		{"inside lan", "10.0.0.5", "clients"},
		{"inside wan", "203.0.113.9", "wan"},
		{"no match", "192.168.99.1", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := inferZoneFromAddress(tc.address, networks); got != tc.want {
				t.Errorf("inferZoneFromAddress(%q) = %q, want %q", tc.address, got, tc.want)
			}
		})
	}
}
