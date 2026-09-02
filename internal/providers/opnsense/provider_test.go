package opnsense

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/intent"
	providers "github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/testutil"
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
	if len(caps) != 4 || caps[0] != "info" || caps[1] != "import" || caps[2] != "check" || caps[3] != "inventory" {
		t.Errorf("Capabilities() = %v, want [info import check inventory]", caps)
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
			testutil.WriteBody(w, systemInfoJSON)
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
		if info.Provider != "opnsense" || info.Version != "24.1.7_2" {
			t.Errorf("info = %+v", info)
		}
		if info.Extra["product"] != "OPNsense" || info.Extra["arch"] != "amd64" {
			t.Errorf("extra = %v", info.Extra)
		}
	})

	t.Run("system info fetch fails", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()

		p := &Provider{}
		_, err := p.Info(context.Background(), providers.ImportOptions{Host: ts.URL, SkipTLSVerify: true})
		if err == nil {
			t.Error("expected error for system info fetch failure")
		}
	})
}

// opnsenseServer returns a test server serving a canned OPNsense API
// (real endpoint shapes: interfaces_info map, paged search_rule rows).
func opnsenseServer(t *testing.T, leases string) *httptest.Server {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/diagnostics/system/system_information":
			testutil.WriteBody(w, systemInfoJSON)
		case "/api/interfaces/overview/interfaces_info":
			testutil.WriteBody(w, `{"interfaces":{
				"lan":{"description":"LAN","dhcp":false,"ipv4":"10.0.0.1/24","ipv4_gateway":"10.0.0.254"},
				"wan":{"description":"WAN","dhcp":true,"ipv4":"203.0.113.1/24","ipv4_gateway":"203.0.113.254"},
				"no-ip":{"description":"","dhcp":false,"ipv4":"","ipv4_gateway":""},
				"bad-cidr":{"description":"","dhcp":false,"ipv4":"999.1.1.1/99","ipv4_gateway":""}
			}}`)
		case "/api/firewall/filter/search_rule":
			testutil.WriteBody(w, `{"total":5,"rows":[
				{"uuid":"u1","enabled":"1","action":"block","description":"Deny LAN to IOT","interface":["lan"],"source_net":"10.0.0.5","destination_net":"203.0.113.9"},
				{"uuid":"u2","enabled":"1","action":"reject","interface":["lan"],"source_net":"10.0.0.6","destination_net":"203.0.113.10"},
				{"uuid":"u3","enabled":"1","action":"pass","description":"allow dns","interface":["lan"],"source_net":"any","destination_net":"any"},
				{"uuid":"u4","enabled":"0","action":"block","interface":["lan"],"source_net":"10.0.0.7","destination_net":"203.0.113.11"},
				{"uuid":"u5","enabled":"1","action":"block","description":"unresolvable endpoints","interface":["lan"],"source_net":"any","destination_net":"203.0.113.9"}
			]}`)
		case "/api/dnsmasq/leases/search":
			testutil.WriteBody(w, leases)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

// wantEmptyTopologyWarning fails unless the empty-topology warning (see
// emptyTopologyWarning) is present in the list.
func wantEmptyTopologyWarning(t *testing.T, warnings []string) {
	t.Helper()
	if !slices.Contains(warnings, emptyTopologyWarning) {
		t.Errorf("warnings = %v, want the empty-topology warning", warnings)
	}
}

// assertionsValid fails unless the imported spec passes the same validation
// a user would hit in `nyx doctor --spec` — a generated spec must never be
// rejected by the engine (e.g. a network_health assertion without a target).
func assertionsValid(t *testing.T, spec *intent.Spec) {
	t.Helper()
	if err := intent.ValidateSpec(spec); err != nil {
		t.Errorf("imported spec fails validation: %v", err)
	}
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
		if err == nil || !strings.Contains(err.Error(), "--client-id and --client-secret are required") {
			t.Errorf("error = %v, want credentials required", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		ts := opnsenseServer(t, `{"leases":[{"mac":"aa","ip":"10.0.0.10","hostname":"laptop"}]}`)
		p := &Provider{}
		opts := providers.ImportOptions{
			Host:          ts.URL,
			ClientID:      "key",
			ClientSecret:  "secret",
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
		// One health assertion per distinct gateway (lan + wan).
		var health int
		for _, a := range spec.Assertions {
			if a.Type == "network_health" && a.Target != "" {
				health++
			}
		}
		if health != 2 {
			t.Errorf("network_health assertions = %d, want 2 (one per distinct gateway): %+v", health, spec.Assertions)
		}
		assertionsValid(t, spec)
		if len(res.Warnings) != 2 {
			t.Errorf("warnings = %v, want 2", res.Warnings)
		}
	})

	t.Run("system info fails", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()
		p := &Provider{}
		_, err := p.ImportSpec(context.Background(), providers.ImportOptions{Host: ts.URL, ClientID: "k", ClientSecret: "s", SkipTLSVerify: true})
		if err == nil || !strings.Contains(err.Error(), "fetching system info") {
			t.Errorf("error = %v, want fetching system info", err)
		}
	})

	t.Run("interfaces fail", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/diagnostics/system/system_information" {
				testutil.WriteBody(w, systemInfoJSON)
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()
		p := &Provider{}
		_, err := p.ImportSpec(context.Background(), providers.ImportOptions{Host: ts.URL, ClientID: "k", ClientSecret: "s", SkipTLSVerify: true})
		if err == nil || !strings.Contains(err.Error(), "fetching interfaces") {
			t.Errorf("error = %v, want fetching interfaces", err)
		}
	})

	t.Run("rules fetch fails", func(t *testing.T) {
		// GetFirewallRules surfaces transport/API errors — a silent "0
		// policies" import would hide revoked keys or an unreachable API.
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/diagnostics/system/system_information":
				testutil.WriteBody(w, systemInfoJSON)
			case "/api/interfaces/overview/interfaces_info":
				testutil.WriteBody(w, `{"interfaces":{"lan":{"ipv4":"10.0.0.1/24"}}}`)
			case "/api/firewall/filter/search_rule":
				w.WriteHeader(http.StatusInternalServerError)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer ts.Close()
		p := &Provider{}
		_, err := p.ImportSpec(context.Background(), providers.ImportOptions{Host: ts.URL, ClientID: "k", ClientSecret: "s", SkipTLSVerify: true})
		if err == nil || !strings.Contains(err.Error(), "fetching firewall rules") {
			t.Errorf("error = %v, want fetching firewall rules", err)
		}
	})

	t.Run("leases fail", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/diagnostics/system/system_information":
				testutil.WriteBody(w, systemInfoJSON)
			case "/api/interfaces/overview/interfaces_info":
				testutil.WriteBody(w, `{"interfaces":{"lan":{"ipv4":"10.0.0.1/24"}}}`)
			case "/api/firewall/filter/search_rule":
				testutil.WriteBody(w, `{"total":0,"rows":[]}`)
			case "/api/dnsmasq/leases/search":
				w.WriteHeader(http.StatusInternalServerError)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer ts.Close()
		p := &Provider{}
		_, err := p.ImportSpec(context.Background(), providers.ImportOptions{Host: ts.URL, ClientID: "k", ClientSecret: "s", SkipTLSVerify: true})
		if err == nil || !strings.Contains(err.Error(), "fetching DHCP leases") {
			t.Errorf("error = %v, want fetching DHCP leases", err)
		}
	})

	t.Run("debug flag is threaded to the client", func(t *testing.T) {
		ts := opnsenseServer(t, `{"leases":[]}`)
		p := &Provider{}
		out := captureStderr(t, func() {
			_, err := p.ImportSpec(context.Background(), providers.ImportOptions{
				Host:          ts.URL,
				ClientID:      "key",
				ClientSecret:  "secret",
				SkipTLSVerify: true,
				Debug:         true,
			})
			if err != nil {
				t.Fatalf("ImportSpec: %v", err)
			}
		})
		// Every raw read of the import goes through the client: system
		// info, interfaces, firewall rules, and the lease route probe.
		for _, want := range []string{
			"[opnsense debug] GET https://",
			"/api/diagnostics/system/system_information",
			"/api/interfaces/overview/interfaces_info",
			"/api/firewall/filter/search_rule",
			"/api/dnsmasq/leases/search",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("stderr missing %q (Debug not threaded): %s", want, out)
			}
		}
	})

	t.Run("no debug output without the flag", func(t *testing.T) {
		ts := opnsenseServer(t, `{"leases":[]}`)
		p := &Provider{}
		out := captureStderr(t, func() {
			if _, err := p.ImportSpec(context.Background(), providers.ImportOptions{
				Host:          ts.URL,
				ClientID:      "key",
				ClientSecret:  "secret",
				SkipTLSVerify: true,
			}); err != nil {
				t.Fatalf("ImportSpec: %v", err)
			}
		})
		if strings.Contains(out, "[opnsense debug]") {
			t.Errorf("debug output without the flag: %s", out)
		}
	})

	// 26.x serves a paged rows shape for interfaces_info; the import must
	// build networks from it instead of silently producing an empty spec.
	t.Run("26.x rows shape yields networks", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/diagnostics/system/system_information":
				testutil.WriteBody(w, systemInfoJSON)
			case "/api/interfaces/overview/interfaces_info":
				testutil.WriteBody(w, `{"total":2,"rowCount":2,"current":1,"rows":[
					{"identifier":"lan","description":"LAN","addr4":"198.51.100.1/24","ipv4":[{"ipaddr":"198.51.100.1/24"}],"gateways":["198.51.100.254"]},
					{"identifier":"opt1","description":"OPT1","addr4":"198.51.100.50/24","ipv4":[{"ipaddr":"198.51.100.50/24"}],"gateways":[]},
					{"identifier":"","description":"Unassigned Interface","addr4":"","ipv4":[]}
				]}`)
			case "/api/firewall/filter/search_rule":
				testutil.WriteBody(w, `{"total":0,"rows":[]}`)
			case "/api/dnsmasq/leases/search":
				testutil.WriteBody(w, `{"leases":[{"mac":"aa","ip":"198.51.100.10","hostname":"laptop"}]}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer ts.Close()
		p := &Provider{}
		res, err := p.ImportSpec(context.Background(), providers.ImportOptions{Host: ts.URL, ClientID: "k", ClientSecret: "s", SkipTLSVerify: true})
		if err != nil {
			t.Fatalf("ImportSpec: %v", err)
		}
		if res.NetworkCount != 2 {
			t.Fatalf("NetworkCount = %d, want 2 (lan + opt1)", res.NetworkCount)
		}
		byName := map[string]intent.Network{}
		for _, n := range res.Spec.Networks {
			byName[n.Name] = n
		}
		lan, ok := byName["lan"]
		if !ok || lan.CIDR != "198.51.100.1/24" || lan.Gateway != "198.51.100.254" {
			t.Errorf("lan network = %+v", lan)
		}
		opt1, ok := byName["opt1"]
		if !ok || opt1.CIDR != "198.51.100.50/24" {
			t.Errorf("opt1 network = %+v", opt1)
		}
		// unassigned (empty identifier) rows must not leak into the spec
		if _, ok := byName[""]; ok {
			t.Error("unassigned interface leaked into the spec")
		}
		// A populated topology must not carry the empty-topology warning.
		if slices.Contains(res.Warnings, emptyTopologyWarning) {
			t.Errorf("empty-topology warning on a populated topology: %v", res.Warnings)
		}
		assertionsValid(t, res.Spec)
	})

	// Live 26.x road test: most interfaces carry no gateway (LAN-side
	// bridges, loopback). The import must emit a network_health assertion
	// only for the distinct gateways that exist — a health assertion with an
	// empty target fails spec validation and would make the import unusable.
	// Two networks sharing one gateway must yield a single health assertion.
	t.Run("health assertions track distinct gateways only", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/diagnostics/system/system_information":
				testutil.WriteBody(w, systemInfoJSON)
			case "/api/interfaces/overview/interfaces_info":
				testutil.WriteBody(w, `{"total":4,"rowCount":4,"current":1,"rows":[
					{"identifier":"opt1","description":"OPT1","addr4":"198.51.100.50/24","ipv4":[{"ipaddr":"198.51.100.50/24"}],"gateways":[]},
					{"identifier":"lo0","description":"Loopback","addr4":"127.0.0.1/8","ipv4":[{"ipaddr":"127.0.0.1/8"}],"gateways":[]},
					{"identifier":"wan","description":"WAN","addr4":"198.51.100.100/24","ipv4":[{"ipaddr":"198.51.100.100/24"}],"gateways":["198.51.100.254"]},
					{"identifier":"wan1","description":"WAN1","addr4":"198.51.100.101/24","ipv4":[{"ipaddr":"198.51.100.101/24"}],"gateways":["198.51.100.254"]}
				]}`)
			case "/api/firewall/filter/search_rule":
				testutil.WriteBody(w, `{"total":0,"rows":[]}`)
			case "/api/dnsmasq/leases/search":
				testutil.WriteBody(w, `{"leases":[]}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer ts.Close()
		p := &Provider{}
		res, err := p.ImportSpec(context.Background(), providers.ImportOptions{Host: ts.URL, ClientID: "k", ClientSecret: "s", SkipTLSVerify: true})
		if err != nil {
			t.Fatalf("ImportSpec: %v", err)
		}
		if res.NetworkCount != 4 {
			t.Fatalf("NetworkCount = %d, want 4", res.NetworkCount)
		}
		var health []string
		for _, a := range res.Spec.Assertions {
			if a.Type == "network_health" {
				health = append(health, a.Target)
			}
		}
		if len(health) != 1 || health[0] != "198.51.100.254" {
			t.Errorf("network_health targets = %v, want [198.51.100.254]", health)
		}
		assertionsValid(t, res.Spec)
	})

	// A 200 OK that decodes to zero networks is the silent-empty-topology
	// failure mode (#57): the import still succeeds (an empty-but-valid spec)
	// but must warn loudly instead of writing a useless spec silently.
	t.Run("empty interfaces map degrades to a warning", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/diagnostics/system/system_information":
				testutil.WriteBody(w, systemInfoJSON)
			case "/api/interfaces/overview/interfaces_info":
				testutil.WriteBody(w, `{"interfaces":{}}`)
			case "/api/firewall/filter/search_rule":
				testutil.WriteBody(w, `{"total":0,"rows":[]}`)
			case "/api/dnsmasq/leases/search":
				testutil.WriteBody(w, `{"leases":[]}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer ts.Close()
		p := &Provider{}
		res, err := p.ImportSpec(context.Background(), providers.ImportOptions{Host: ts.URL, ClientID: "k", ClientSecret: "s", SkipTLSVerify: true})
		if err != nil {
			t.Fatalf("ImportSpec: %v", err)
		}
		if res.NetworkCount != 0 {
			t.Errorf("NetworkCount = %d, want 0", res.NetworkCount)
		}
		wantEmptyTopologyWarning(t, res.Warnings)
	})
}

// importStatusServer serves the canned import endpoints, returning the
// given status codes on the firewall-rules and lease routes (a 200 carries
// the matching canned body; a 403 the client's permission-denied body; a 401
// the auth-failure body) and defaulting every other path to 404. The canned
// shapes match opnsenseServer.
func importStatusServer(t *testing.T, rulesStatus, leasesStatus int) *httptest.Server {
	t.Helper()
	const (
		rulesBody = `{"total":0,"rows":[]}`
		leaseBody = `{"leases":[{"mac":"aa","ip":"198.51.100.10","hostname":"laptop"}]}`
	)
	writeStatus := func(w http.ResponseWriter, status int, okBody string) {
		w.WriteHeader(status)
		switch status {
		case http.StatusOK:
			testutil.WriteBody(w, okBody)
		case http.StatusForbidden:
			testutil.WriteBody(w, `{"error":"page privilege denied"}`)
		case http.StatusUnauthorized:
			testutil.WriteBody(w, `{"error":"authentication failed"}`)
		}
	}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/diagnostics/system/system_information":
			testutil.WriteBody(w, systemInfoJSON)
		case "/api/interfaces/overview/interfaces_info":
			testutil.WriteBody(w, `{"interfaces":{"lan":{"ipv4":"10.0.0.1/24"}}}`)
		case "/api/firewall/filter/search_rule":
			writeStatus(w, rulesStatus, rulesBody)
		case "/api/dnsmasq/leases/search", "/api/dhcpd/leases":
			writeStatus(w, leasesStatus, leaseBody)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

// TestImportSpecPrivilegeDegradation covers #58: a least-privilege
// (Dashboard-only) API user gets stable 403s on the firewall-rules and
// lease routes. The import degrades to a zero-policy, zero-client spec with
// explicit warnings instead of a fatal error — the gateway is reachable and
// the key is valid, so the import → audit loop must stay usable.
func TestImportSpecPrivilegeDegradation(t *testing.T) {
	t.Run("stable 403 on rules and leases degrades to warnings", func(t *testing.T) {
		ts := importStatusServer(t, http.StatusForbidden, http.StatusForbidden)
		p := &Provider{}
		res, err := p.ImportSpec(context.Background(), providers.ImportOptions{Host: ts.URL, ClientID: "k", ClientSecret: "s", SkipTLSVerify: true})
		if err != nil {
			t.Fatalf("ImportSpec: %v (a stable privilege 403 must degrade, not fail)", err)
		}
		if res.NetworkCount != 1 {
			t.Errorf("NetworkCount = %d, want 1 (lan)", res.NetworkCount)
		}
		if res.PolicyCount != 0 {
			t.Errorf("PolicyCount = %d, want 0", res.PolicyCount)
		}
		if res.ClientCount != 0 {
			t.Errorf("ClientCount = %d, want 0 (no lease privilege)", res.ClientCount)
		}
		if len(res.Spec.Policies) != 0 || len(res.Spec.Networks) != 1 {
			t.Fatalf("spec = %d networks / %d policies, want 1/0", len(res.Spec.Networks), len(res.Spec.Policies))
		}
		if len(res.Warnings) != 4 {
			t.Errorf("warnings = %v, want 4 (2 degrade + 2 standard)", res.Warnings)
		}
		for _, want := range []string{"firewall rules unavailable:", "permission denied", "DHCP leases unavailable:"} {
			if !slices.ContainsFunc(res.Warnings, func(w string) bool { return strings.Contains(w, want) }) {
				t.Errorf("warnings = %v, want one containing %q", res.Warnings, want)
			}
		}
	})

	// Rules 403 only: leases still decode, so the client count survives and
	// exactly one degrade warning is emitted.
	t.Run("stable 403 on rules only keeps the lease count", func(t *testing.T) {
		ts := importStatusServer(t, http.StatusForbidden, http.StatusOK)
		p := &Provider{}
		res, err := p.ImportSpec(context.Background(), providers.ImportOptions{Host: ts.URL, ClientID: "k", ClientSecret: "s", SkipTLSVerify: true})
		if err != nil {
			t.Fatalf("ImportSpec: %v", err)
		}
		if res.ClientCount != 1 {
			t.Errorf("ClientCount = %d, want 1 (leases readable)", res.ClientCount)
		}
		if !slices.ContainsFunc(res.Warnings, func(w string) bool { return strings.Contains(w, "firewall rules unavailable:") }) {
			t.Errorf("warnings = %v, want the rules degrade warning", res.Warnings)
		}
		if slices.ContainsFunc(res.Warnings, func(w string) bool { return strings.Contains(w, "DHCP leases unavailable:") }) {
			t.Errorf("warnings = %v, must not mention leases", res.Warnings)
		}
	})

	// 401 stays fatal even on the rules route: an authentication failure
	// means the key itself is broken — degrading would produce a
	// zero-policy spec from a gateway we cannot trust to be talking to us.
	t.Run("401 on rules is fatal", func(t *testing.T) {
		ts := importStatusServer(t, http.StatusUnauthorized, http.StatusOK)
		p := &Provider{}
		_, err := p.ImportSpec(context.Background(), providers.ImportOptions{Host: ts.URL, ClientID: "k", ClientSecret: "s", SkipTLSVerify: true})
		if err == nil || !strings.Contains(err.Error(), "fetching firewall rules") || !strings.Contains(err.Error(), "authentication failed") {
			t.Errorf("error = %v, want fatal fetching firewall rules / authentication failed", err)
		}
	})
}

func TestProviderCheck(t *testing.T) {
	t.Run("success with empty spec", func(t *testing.T) {
		// No interfaces with IPs → no networks → no assertions → the audit
		// engine runs with an empty assertion list (hermetic, no network I/O).
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/diagnostics/system/system_information":
				testutil.WriteBody(w, systemInfoJSON)
			case "/api/interfaces/overview/interfaces_info":
				testutil.WriteBody(w, `{"interfaces":{}}`)
			case "/api/firewall/filter/search_rule":
				testutil.WriteBody(w, `{"total":0,"rows":[]}`)
			case "/api/dnsmasq/leases/search":
				testutil.WriteBody(w, `{"leases":[]}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer ts.Close()

		p := &Provider{}
		res, err := p.Check(context.Background(), providers.ImportOptions{
			Host: ts.URL, ClientID: "k", ClientSecret: "s", SkipTLSVerify: true,
		})
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if res.Report == nil {
			t.Fatal("Report is nil")
		}
		// 3 = the two standing import advisories + the empty-topology
		// warning (empty interfaces map), which Check forwards verbatim.
		if len(res.Warnings) != 3 {
			t.Errorf("warnings = %v, want 3", res.Warnings)
		}
	})

	t.Run("import fails", func(t *testing.T) {
		p := &Provider{}
		_, err := p.Check(context.Background(), providers.ImportOptions{Host: "https://127.0.0.1:1", ClientID: "k", ClientSecret: "s"})
		if err == nil {
			t.Error("expected import failure to propagate")
		}
	})
}

func TestProviderInventory(t *testing.T) {
	t.Run("missing host", func(t *testing.T) {
		p := &Provider{}
		_, err := p.Inventory(context.Background(), providers.ImportOptions{})
		if err == nil || !strings.Contains(err.Error(), "--host is required") {
			t.Errorf("error = %v, want --host is required", err)
		}
	})

	t.Run("missing credentials", func(t *testing.T) {
		p := &Provider{}
		_, err := p.Inventory(context.Background(), providers.ImportOptions{Host: "h"})
		if err == nil || !strings.Contains(err.Error(), "--client-id and --client-secret are required") {
			t.Errorf("error = %v, want credentials required", err)
		}
	})

	t.Run("success", func(t *testing.T) {
		ts := opnsenseServer(t, `{"leases":[{"mac":"aa","ip":"10.0.0.10","hostname":"laptop"},{"mac":"bb","ip":"10.0.0.11","hostname":"nas"}]}`)
		p := &Provider{}
		res, err := p.Inventory(context.Background(), providers.ImportOptions{
			Host: ts.URL, ClientID: "key", ClientSecret: "secret", SkipTLSVerify: true,
		})
		if err != nil {
			t.Fatalf("Inventory: %v", err)
		}
		if res.Site != "opnsense-firewall" {
			t.Errorf("Site = %q, want opnsense-firewall", res.Site)
		}
		if res.ClientCount != 2 {
			t.Errorf("ClientCount = %d, want 2", res.ClientCount)
		}
		inv := res.Inventory
		if inv == nil {
			t.Fatal("Inventory is nil")
		}
		if inv.ControllerVersion != "24.1.7_2" {
			t.Errorf("ControllerVersion = %q, want 24.1.7_2", inv.ControllerVersion)
		}
		if len(inv.Devices) != 2 {
			t.Fatalf("Devices = %+v, want 2 (lan + wan)", inv.Devices)
		}
		if inv.Devices[0].Type != "gateway" || inv.Devices[0].Name != "lan" || inv.Devices[0].IP != "10.0.0.1" {
			t.Errorf("device[0] = %+v", inv.Devices[0])
		}
		if inv.NetworkGateways["lan"] != "10.0.0.254" {
			t.Errorf("NetworkGateways = %v", inv.NetworkGateways)
		}
		if len(res.Warnings) != 0 {
			t.Errorf("Warnings = %v, want none on a clean fetch", res.Warnings)
		}
		if !strings.Contains(res.Human, "== Networks (2) ==") || !strings.Contains(res.Human, "2 active clients") {
			t.Errorf("Human render missing sections:\n%s", res.Human)
		}
	})

	t.Run("best-effort degradation", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/interfaces/overview/interfaces_info":
				testutil.WriteBody(w, `{"interfaces":{"lan":{"ipv4":"10.0.0.1/24"}}}`)
			case "/api/diagnostics/system/system_information":
				w.WriteHeader(http.StatusInternalServerError)
			case "/api/firewall/filter/search_rule":
				w.WriteHeader(http.StatusInternalServerError)
			case "/api/dnsmasq/leases/search":
				w.WriteHeader(http.StatusInternalServerError)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer ts.Close()
		p := &Provider{}
		res, err := p.Inventory(context.Background(), providers.ImportOptions{
			Host: ts.URL, ClientID: "k", ClientSecret: "s", SkipTLSVerify: true,
		})
		if err != nil {
			t.Fatalf("Inventory: %v (only interfaces is fatal)", err)
		}
		if len(res.Warnings) != 3 {
			t.Errorf("Warnings = %v, want 3 (system info, rules, leases)", res.Warnings)
		}
		if len(res.Inventory.Devices) != 1 {
			t.Errorf("Devices = %+v, want 1 (interfaces still fetched)", res.Inventory.Devices)
		}
		if res.ClientCount != 0 {
			t.Errorf("ClientCount = %d, want 0 when leases failed", res.ClientCount)
		}
	})

	t.Run("interfaces fatal", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()
		p := &Provider{}
		_, err := p.Inventory(context.Background(), providers.ImportOptions{Host: ts.URL, ClientID: "k", ClientSecret: "s", SkipTLSVerify: true})
		if err == nil {
			t.Error("expected interfaces failure to be fatal")
		}
	})

	// A 200 OK that decodes to zero networks must not render as a silently
	// empty topology (#57): the snapshot carries a warning and the human
	// render surfaces it.
	t.Run("empty interfaces map degrades to a warning", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/diagnostics/system/system_information":
				testutil.WriteBody(w, systemInfoJSON)
			case "/api/interfaces/overview/interfaces_info":
				testutil.WriteBody(w, `{"interfaces":{}}`)
			case "/api/firewall/filter/search_rule":
				testutil.WriteBody(w, `{"total":0,"rows":[]}`)
			case "/api/dnsmasq/leases/search":
				testutil.WriteBody(w, `{"leases":[]}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer ts.Close()
		p := &Provider{}
		res, err := p.Inventory(context.Background(), providers.ImportOptions{Host: ts.URL, ClientID: "k", ClientSecret: "s", SkipTLSVerify: true})
		if err != nil {
			t.Fatalf("Inventory: %v", err)
		}
		wantEmptyTopologyWarning(t, res.Warnings)
		// The renderer must NOT duplicate the warning: the CLI layer prints
		// warnings to stderr once and the JSON surface keeps them structured
		// (#60). The human block shows the empty section instead.
		if strings.Contains(res.Human, emptyTopologyWarning) {
			t.Errorf("Human render must not duplicate the warning:\n%s", res.Human)
		}
		if !strings.Contains(res.Human, "== Networks (0) ==") {
			t.Errorf("Human render must still show the empty section:\n%s", res.Human)
		}
	})

	// #59: the CLI's --debug flag must reach the client on the inventory
	// surface too — Inventory is the only read that operator may need to
	// inspect (e.g. the raw interfaces_info payload).
	t.Run("debug flag is threaded to the client", func(t *testing.T) {
		ts := opnsenseServer(t, `{"leases":[]}`)
		p := &Provider{}
		out := captureStderr(t, func() {
			if _, err := p.Inventory(context.Background(), providers.ImportOptions{
				Host:          ts.URL,
				ClientID:      "key",
				ClientSecret:  "secret",
				SkipTLSVerify: true,
				Debug:         true,
			}); err != nil {
				t.Fatalf("Inventory: %v", err)
			}
		})
		for _, want := range []string{"[opnsense debug] GET https://", "/api/interfaces/overview/interfaces_info"} {
			if !strings.Contains(out, want) {
				t.Errorf("stderr missing %q (Debug not threaded): %s", want, out)
			}
		}
	})

	// Same guard on the client fetch, independent of the provider wrapper.
	t.Run("FetchInventory empty topology warns", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/interfaces/overview/interfaces_info":
				testutil.WriteBody(w, `{"total":1,"rowCount":1,"current":1,"rows":[{"identifier":"","description":"Unassigned Interface","addr4":"","ipv4":[]}]}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		snap, err := c.FetchInventory(context.Background())
		if err != nil {
			t.Fatalf("FetchInventory: %v", err)
		}
		if len(snap.Interfaces) != 0 {
			t.Errorf("Interfaces = %+v, want 0", snap.Interfaces)
		}
		wantEmptyTopologyWarning(t, snap.Warnings)
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
