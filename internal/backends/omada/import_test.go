package omada

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/intent"
)

func TestInferZone(t *testing.T) {
	cases := []struct {
		name string
		n    Network
		want string
	}{
		{"name", Network{Name: "mgmt"}, "management"},
		{"name", Network{Name: "manage-net"}, "management"},
		{"name", Network{Name: "iot"}, "iot"},
		{"name", Network{Name: "guest-wifi"}, "guest"},
		{"name", Network{Name: "server-farm"}, "servers"},
		{"name", Network{Name: "media room"}, "media"},
		{"name", Network{Name: "theater"}, "media"},
		{"name", Network{Name: "gaming"}, "gaming"},
		{"name", Network{Name: "mobile"}, "personal"},
		{"name", Network{Name: "wifi"}, "personal"},
		{"isolated fallback", Network{Name: "vlan10", Isolated: true}, "isolated"},
		{"trusted default", Network{Name: "vlan10"}, "trusted"},
	}
	for _, tc := range cases {
		t.Run(tc.name+"/"+tc.n.Name, func(t *testing.T) {
			if got := inferZone(tc.n); got != tc.want {
				t.Errorf("inferZone(%+v) = %q, want %q", tc.n, got, tc.want)
			}
		})
	}
}

func TestSanitizeName(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"Trusted(Default)", "trusted"},
		{"  IoT  ", "iot"},
		{"Trusted_VLAN_10", "trusted-vlan-10"},
		{"A&B", "ab"},
		{"hello world", "hello-world"},
		{in: "", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := sanitizeName(tc.in); got != tc.want {
				t.Errorf("sanitizeName(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestFindNetwork(t *testing.T) {
	nets := []Network{
		{ID: "n1", Name: "LAN(Default)"},
		{ID: "n2", Name: "Trusted"},
	}
	if n, ok := FindNetwork(nets, "lan"); !ok || n.ID != "n1" {
		t.Errorf("slug match = %+v, %v; want LAN(Default)", n, ok)
	}
	if n, ok := FindNetwork(nets, "Trusted"); !ok || n.ID != "n2" {
		t.Errorf("display match = %+v, %v; want Trusted", n, ok)
	}
	if _, ok := FindNetwork(nets, "missing"); ok {
		t.Error("missing name should not match")
	}
}

func TestResolveRuleEndpoint(t *testing.T) {
	nets := map[string]intent.Network{"net-1": {Name: "lan"}}
	cases := []struct {
		name   string
		epType string
		nameEP string
		ids    []string
		want   string
	}{
		{"name wins", "inet", "Guest", []string{"net-1"}, "guest"},
		{"known network id", "inet", "", []string{"net-1"}, "lan"},
		{"unknown id kept", "inet", "", []string{"other"}, "other"},
		{"fallback to type", "inet", "", nil, "inet"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveRuleEndpoint(tc.epType, tc.nameEP, tc.ids, nets)
			if got != tc.want {
				t.Errorf("resolveRuleEndpoint(%q,%q,%v) = %q, want %q", tc.epType, tc.nameEP, tc.ids, got, tc.want)
			}
		})
	}
}

func TestSelectSite(t *testing.T) {
	sites := []Site{{ID: "a", Name: "HQ"}, {ID: "b", Name: "Branch"}}

	t.Run("empty name picks first", func(t *testing.T) {
		s, err := SelectSite(sites, "")
		if err != nil || s.ID != "a" {
			t.Errorf("SelectSite(\"\") = %+v, %v; want first site", s, err)
		}
	})

	t.Run("case-insensitive match", func(t *testing.T) {
		s, err := SelectSite(sites, "BRANCH")
		if err != nil || s.ID != "b" {
			t.Errorf("SelectSite(\"BRANCH\") = %+v, %v; want site b", s, err)
		}
	})

	t.Run("missing site error", func(t *testing.T) {
		_, err := SelectSite(sites, "Nope")
		if err == nil || !strings.Contains(err.Error(), `site "Nope" not found`) {
			t.Errorf("SelectSite(\"Nope\") error = %v, want not-found", err)
		}
	})
}

func TestMaxInt(t *testing.T) {
	if got := maxInt(3, 20); got != 20 {
		t.Errorf("maxInt(3,20) = %d, want 20", got)
	}
	if got := maxInt(20, 3); got != 20 {
		t.Errorf("maxInt(20,3) = %d, want 20", got)
	}
}

func TestPoliciesFromRules(t *testing.T) {
	networks := []Network{
		{ID: "n1", Name: "Trusted", GatewaySubnet: "10.0.0.1/24"},
		{ID: "n2", Name: "IoT", GatewaySubnet: "10.0.1.1/24"},
	}
	rules := []ACLRule{
		{Name: "Block IoT", Policy: ACLPolicyDeny, Status: true, SourceType: "network", SourceName: "IoT", DestType: "network", DestName: "Trusted"},
		{Name: "Allow Web", Policy: ACLPolicyPermit, Status: true, SourceType: "network", SourceIDs: []string{"n2"}, DestType: "network", DestIDs: []string{"n1"}},
		{Name: "Disabled", Policy: ACLPolicyDeny, Status: false},
		{Name: "Unresolved", Policy: ACLPolicyDeny, Status: true, SourceType: "inet"},
	}

	got := PoliciesFromRules(rules, networks)
	if len(got) != 3 {
		t.Fatalf("policies = %+v, want 3 (disabled skipped)", got)
	}
	byName := map[string]intent.Policy{}
	for _, p := range got {
		byName[p.Name] = p
	}
	if p := byName["block-iot"]; p.From != "iot" || p.To != "trusted" || p.Action != "deny" {
		t.Errorf("block-iot = %+v, want iot->trusted deny", p)
	}
	if p := byName["allow-web"]; p.From != "iot" || p.To != "trusted" || p.Action != "allow" {
		t.Errorf("allow-web = %+v, want iot->trusted allow via network ids", p)
	}
	if p := byName["unresolved"]; p.From != "inet" {
		t.Errorf("unresolved = %+v, want endpoint fallback to source type", p)
	}
}

func TestPoliciesFromRulesUnknownPolicyDefaultsDeny(t *testing.T) {
	got := PoliciesFromRules([]ACLRule{{
		Name: "odd", Policy: ACLPolicy(9), Status: true, SourceType: "network", SourceName: "a", DestType: "network", DestName: "b",
	}}, nil)
	if len(got) != 1 || got[0].Action != "deny" {
		t.Errorf("unknown policy = %+v, want deny fallback", got)
	}
}

func TestBuildAssertions(t *testing.T) {
	networks := []intent.Network{
		{Name: "lan", CIDR: "10.0.0.0/24", Gateway: "10.0.0.1"},
		{Name: "iot", CIDR: "10.0.1.0/24", Gateway: ""},
	}
	omadaNets := []Network{
		{ID: "n1", Name: "Lan", GatewaySubnet: "10.0.0.1/24"},
		{ID: "n2", Name: "IoT", GatewaySubnet: "10.0.1.1/24"},
	}
	clients := []ConnectedClient{
		{NetworkName: "Lan", IP: "10.0.0.10"},
		{NetworkName: "Lan", IP: "10.0.0.11"},
		{SSID: "IoT-Guest", IP: "10.0.1.10"},
	}
	rules := []ACLRule{
		{Name: "lan-iot-deny", Policy: ACLPolicyDeny, Status: true, SourceType: "network", SourceName: "lan", DestType: "network", DestName: "iot"},
		{Name: "disabled", Policy: ACLPolicyDeny, Status: false},
		{Name: "allow-web", Policy: ACLPolicyPermit, Status: true, SourceType: "network", SourceName: "lan", DestType: "network", DestName: "iot"},
		{Name: "unresolved", Policy: ACLPolicyDeny, Status: true},
	}
	netsByID := map[string]intent.Network{"n1": networks[0], "n2": networks[1]}

	got := buildAssertions(networks, omadaNets, clients, rules, netsByID)

	var subnet, route, isolation, internet int
	for _, a := range got {
		switch a.Type {
		case "subnet_discovery":
			subnet++
			if a.ExpectHostsMin == nil || a.ExpectHostsMax == nil {
				t.Errorf("subnet_discovery %s missing bounds", a.Network)
			}
		case "route_check":
			route++
			if a.Target == "8.8.8.8" {
				internet++
			}
		case "isolation":
			isolation++
			if a.Expect != "deny" || a.From != "lan" || a.To != "iot" {
				t.Errorf("isolation assertion = %+v, want deny lan->iot", a)
			}
		}
	}
	if subnet != 2 {
		t.Errorf("subnet_discovery count = %d, want 2", subnet)
	}
	if route != 2 {
		t.Errorf("route_check count = %d, want 2 (gateway + internet; iot has no gateway)", route)
	}
	if isolation != 1 {
		t.Errorf("isolation count = %d, want 1 (unresolved and disabled skipped, accept excluded)", isolation)
	}
	if internet != 1 {
		t.Errorf("internet route_check count = %d, want 1", internet)
	}
}

func TestImportSpecEndToEnd(t *testing.T) {
	var paths []string
	var csrfSeen string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if csrf := r.Header.Get("Csrf-Token"); csrf != "" {
			csrfSeen = csrf
		}
		switch r.URL.Path {
		case "/api/info":
			w.Write([]byte(testInfoResponse))
		case "/abc123/api/v2/login":
			writeEnvelope(w, 0, "", `{"token":"t1"}`)
		case "/abc123/api/v2/logout":
			writeEnvelope(w, 0, "", "null")
		case "/abc123/api/v2/sites":
			writeEnvelope(w, 0, "", `{"totalRows":2,"data":[{"id":"s1","name":"HQ"},{"id":"s2","name":"Branch"}]}`)
		case "/abc123/api/v2/sites/s1/setting/lan/networks":
			writeEnvelope(w, 0, "", `{"totalRows":2,"data":[
				{"id":"n1","name":"Trusted","gatewaySubnet":"10.0.0.1/24","vlan":10},
				{"id":"n2","name":"IoT","gatewaySubnet":"10.0.1.1/24","vlan":20}
			]}`)
		case "/abc123/api/v2/sites/s1/setting/firewall/acls":
			if r.URL.Query().Get("type") == "0" {
				writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
				return
			}
			writeEnvelope(w, 0, "", `{"totalRows":3,"data":[
				{"id":"a1","name":"IoT to Trusted","status":true,"policy":0,"sourceType":"network","sourceIds":["n2"],"destinationType":"network","destinationIds":["n1"]},
				{"id":"a2","name":"Trusted to IoT web","status":true,"policy":1,"sourceType":"network","sourceIds":["n1"],"destinationType":"network","destinationIds":["n2"]},
				{"id":"a3","name":"Disabled rule","status":false,"policy":0}
			]}`)
		case "/abc123/api/v2/sites/s1/clients":
			writeEnvelope(w, 0, "", `{"totalRows":1,"data":[
				{"mac":"aa:bb:cc:dd:ee:ff","ip":"10.0.0.50","networkName":"Trusted"}
			]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
			writeEnvelope(w, -1101, "not found", "null")
		}
	}))
	defer ts.Close()

	got, err := ImportSpec(context.Background(), ts.URL, "admin", "pw", "hq", false, true, "", nil)
	if err != nil {
		t.Fatalf("ImportSpec: %v", err)
	}
	if got.Site.Name != "HQ" {
		t.Errorf("Site.Name = %q, want HQ", got.Site.Name)
	}
	if got.NetworkCount != 2 || got.ACLRuleCount != 3 || got.ClientCount != 1 {
		t.Errorf("counts = nets %d acl %d clients %d; want 2/3/1 (rule count includes disabled)",
			got.NetworkCount, got.ACLRuleCount, got.ClientCount)
	}
	if csrfSeen != "t1" {
		t.Errorf("Csrf-Token seen = %q, want t1 (login token reused)", csrfSeen)
	}
	if got.Spec == nil {
		t.Fatal("Spec is nil")
	}
	if len(got.Spec.Networks) != 2 {
		t.Fatalf("spec networks = %+v, want 2", got.Spec.Networks)
	}
	if got.Spec.Networks[0].Name != "trusted" || got.Spec.Networks[0].CIDR != "10.0.0.0/24" ||
		got.Spec.Networks[0].Gateway != "10.0.0.1" || got.Spec.Networks[0].Zone != "trusted" {
		t.Errorf("network[0] = %+v", got.Spec.Networks[0])
	}
	if got.Spec.Networks[1].Name != "iot" {
		t.Errorf("network[1].Name = %q, want iot", got.Spec.Networks[1].Name)
	}
	if len(got.Spec.Policies) != 2 {
		t.Fatalf("policies = %+v, want 2 (deny + accept, disabled skipped)", got.Spec.Policies)
	}
	actions := map[string]string{}
	for _, p := range got.Spec.Policies {
		actions[p.Name] = p.Action
	}
	if actions["iot-to-trusted"] != "deny" || actions["trusted-to-iot-web"] != "allow" {
		t.Errorf("policy actions = %v, want deny + allow", actions)
	}
	if len(got.Spec.Assertions) < 4 {
		t.Errorf("assertions = %+v, want at least subnet+route+isolation+internet", got.Spec.Assertions)
	}
	if len(got.Warnings) != 0 {
		t.Errorf("warnings = %v, want none", got.Warnings)
	}
	if len(paths) < 8 {
		t.Errorf("expected a full request sequence, got %v", paths)
	}
}

func TestImportSpecErrors(t *testing.T) {
	t.Run("client init fails", func(t *testing.T) {
		_, err := ImportSpec(context.Background(), "https://127.0.0.1:1", "a", "b", "", true, true, "", nil)
		if err == nil {
			t.Error("expected error for unreachable controller")
		}
	})

	t.Run("login fails", func(t *testing.T) {
		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/info":
				w.Write([]byte(testInfoResponse))
			case "/abc123/api/v2/login":
				writeEnvelope(w, -30109, "bad", "null")
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer ts.Close()
		_, err := ImportSpec(context.Background(), ts.URL, "admin", "bad", "", true, true, "", nil)
		if err == nil || !strings.Contains(err.Error(), "login failed") {
			t.Errorf("error = %v, want login failed", err)
		}
	})

	t.Run("sites fetch fails", func(t *testing.T) {
		ts := serverResponding(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/info":
				w.Write([]byte(testInfoResponse))
			case "/abc123/api/v2/login":
				writeEnvelope(w, 0, "", `{"token":"t"}`)
			case "/abc123/api/v2/sites":
				writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
			}
		})
		defer ts.Close()
		_, err := ImportSpec(context.Background(), ts.URL, "a", "b", "", true, true, "", nil)
		if err == nil || !strings.Contains(err.Error(), "fetching sites") {
			t.Errorf("error = %v, want fetching sites", err)
		}
	})

	t.Run("missing site name", func(t *testing.T) {
		ts := serverResponding(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/info":
				w.Write([]byte(testInfoResponse))
			case "/abc123/api/v2/login":
				writeEnvelope(w, 0, "", `{"token":"t"}`)
			case "/abc123/api/v2/sites":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
			default:
				writeEnvelope(w, 0, "", `{}`)
			}
		})
		defer ts.Close()
		_, err := ImportSpec(context.Background(), ts.URL, "a", "b", "Other", true, true, "", nil)
		if err == nil || !strings.Contains(err.Error(), `"Other" not found`) {
			t.Errorf("error = %v, want site not found", err)
		}
	})

	t.Run("no networks", func(t *testing.T) {
		ts := serverResponding(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/info":
				w.Write([]byte(testInfoResponse))
			case "/abc123/api/v2/login":
				writeEnvelope(w, 0, "", `{"token":"t"}`)
			case "/abc123/api/v2/sites":
				writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
			case "/abc123/api/v2/sites/s1/setting/lan/networks":
				writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		})
		defer ts.Close()
		_, err := ImportSpec(context.Background(), ts.URL, "a", "b", "", true, true, "", nil)
		if err == nil || !strings.Contains(err.Error(), "fetching networks") {
			t.Errorf("error = %v, want fetching networks", err)
		}
	})
}

func TestImportSpecWarnings(t *testing.T) {
	ts := serverResponding(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/info":
			w.Write([]byte(testInfoResponse))
		case "/abc123/api/v2/login":
			writeEnvelope(w, 0, "", `{"token":"t"}`)
		case "/abc123/api/v2/logout":
			writeEnvelope(w, 0, "", "null")
		case "/abc123/api/v2/sites":
			writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/abc123/api/v2/sites/s1/setting/lan/networks":
			writeEnvelope(w, 0, "", `{"totalRows":2,"data":[
				{"id":"n1","name":"Trusted","gatewaySubnet":"10.0.0.1/24"},
				{"id":"n2","name":"IoT-NoSubnet"}
			]}`)
		case "/abc123/api/v2/sites/s1/setting/firewall/acls":
			writeEnvelope(w, -1000, "expired", "null")
		case "/abc123/api/v2/sites/s1/clients":
			writeEnvelope(w, -1000, "expired", "null")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer ts.Close()

	got, err := ImportSpec(context.Background(), ts.URL, "a", "b", "", true, true, "", nil)
	if err != nil {
		t.Fatalf("ImportSpec: %v", err)
	}
	if got.NetworkCount != 2 {
		t.Errorf("NetworkCount = %d, want 2", got.NetworkCount)
	}
	if len(got.Spec.Networks) != 1 {
		t.Errorf("spec networks = %d, want 1 (one skipped for missing subnet)", len(got.Spec.Networks))
	}
	var hasACLWarn, hasGwWarn, hasClientWarn, hasSubnetWarn bool
	for _, w := range got.Warnings {
		switch {
		case strings.Contains(w, "gateway ACL"):
			hasGwWarn = true
		case strings.Contains(w, "ACL"):
			hasACLWarn = true
		case strings.Contains(w, "clients"):
			hasClientWarn = true
		case strings.Contains(w, "no subnet"):
			hasSubnetWarn = true
		}
	}
	if !hasACLWarn || !hasGwWarn || !hasClientWarn || !hasSubnetWarn {
		t.Errorf("warnings = %v, want ACL, gateway ACL, client, and subnet warnings (%v/%v/%v/%v)",
			got.Warnings, hasACLWarn, hasGwWarn, hasClientWarn, hasSubnetWarn)
	}
}

func TestImportSpecGatewayACLDisabledWarning(t *testing.T) {
	ts := serverResponding(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/info":
			w.Write([]byte(testInfoResponse))
		case "/abc123/api/v2/login":
			writeEnvelope(w, 0, "", `{"token":"t"}`)
		case "/abc123/api/v2/logout":
			writeEnvelope(w, 0, "", "null")
		case "/abc123/api/v2/sites":
			writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/abc123/api/v2/sites/s1/setting/lan/networks":
			writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"n1","name":"LAN","gatewaySubnet":"10.0.0.1/24"}]}`)
		case "/abc123/api/v2/sites/s1/setting/firewall/acls":
			if r.URL.Query().Get("type") == "0" {
				writeEnvelope(w, 0, "", `{"totalRows":0,"data":[],"aclDisable":true}`)
				return
			}
			writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
		case "/abc123/api/v2/sites/s1/clients":
			writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	defer ts.Close()

	got, err := ImportSpec(context.Background(), ts.URL, "a", "b", "", false, true, "", nil)
	if err != nil {
		t.Fatalf("ImportSpec: %v", err)
	}
	found := false
	for _, w := range got.Warnings {
		if strings.Contains(w, "gateway ACL feature is disabled") {
			found = true
		}
	}
	if !found {
		t.Errorf("warnings = %v, want aclDisable warning", got.Warnings)
	}
}

func serverResponding(h http.HandlerFunc) *httptest.Server {
	return httptest.NewTLSServer(h)
}
