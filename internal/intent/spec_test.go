package intent

import (
	"strings"
	"testing"
)

func TestParseValidSpec(t *testing.T) {
	// Uses testdata/valid_spec.yaml — exercises LoadSpec + ParseSpec together
	spec, err := LoadSpec("../../testdata/valid_spec.yaml")
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if spec.Site != "test-lab" {
		t.Errorf("expected site 'test-lab', got %q", spec.Site)
	}
	if len(spec.Networks) != 2 {
		t.Errorf("expected 2 networks, got %d", len(spec.Networks))
	}
	if len(spec.VPN) != 1 {
		t.Errorf("expected 1 vpn, got %d", len(spec.VPN))
	}
	if len(spec.Policies) != 1 {
		t.Errorf("expected 1 policy, got %d", len(spec.Policies))
	}
	if len(spec.Assertions) != 3 {
		t.Errorf("expected 3 assertions, got %d", len(spec.Assertions))
	}
}

func TestLoadSpecInvalidFile(t *testing.T) {
	// Uses testdata/invalid_spec.yaml — bad CIDR triggers validation error
	_, err := LoadSpec("../../testdata/invalid_spec.yaml")
	if err == nil {
		t.Fatal("expected error loading invalid spec file")
	}
}

func TestParseInvalidVersion(t *testing.T) {
	yaml := []byte(`
version: 99
site: test
networks: []
`)
	_, err := ParseSpec(yaml)
	if err == nil {
		t.Fatal("expected error for invalid version")
	}
}

func TestParseMissingSite(t *testing.T) {
	yaml := []byte(`
version: 1
networks: []
`)
	_, err := ParseSpec(yaml)
	if err == nil {
		t.Fatal("expected error for missing site")
	}
}

func TestParseInvalidCIDR(t *testing.T) {
	yaml := []byte(`
version: 1
site: test
networks:
  - name: bad
    cidr: not-a-cidr
    zone: test
`)
	_, err := ParseSpec(yaml)
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestParseDuplicateNetworkName(t *testing.T) {
	yaml := []byte(`
version: 1
site: test
networks:
  - name: dup
    cidr: 10.0.1.0/24
    zone: a
  - name: dup
    cidr: 10.0.2.0/24
    zone: b
`)
	_, err := ParseSpec(yaml)
	if err == nil {
		t.Fatal("expected error for duplicate network name")
	}
}

func TestParseInvalidPolicyAction(t *testing.T) {
	yaml := []byte(`
version: 1
site: test
networks: []
policies:
  - name: bad
    from: a
    to: b
    action: maybe
`)
	_, err := ParseSpec(yaml)
	if err == nil {
		t.Fatal("expected error for invalid policy action")
	}
}

func TestParseInvalidAssertionType(t *testing.T) {
	yaml := []byte(`
version: 1
site: test
networks: []
assertions:
  - type: bogus_type
`)
	_, err := ParseSpec(yaml)
	if err == nil {
		t.Fatal("expected error for invalid assertion type")
	}
}

func TestNetworkByName(t *testing.T) {
	spec := &Spec{
		Networks: []Network{
			{Name: "mgmt", CIDR: "10.0.10.0/24"},
			{Name: "clients", CIDR: "10.0.20.0/24"},
		},
	}
	n := spec.NetworkByName("clients")
	if n == nil {
		t.Fatal("expected to find 'clients' network")
	}
	if n.CIDR != "10.0.20.0/24" {
		t.Errorf("wrong CIDR: %s", n.CIDR)
	}
	if spec.NetworkByName("nonexistent") != nil {
		t.Error("expected nil for nonexistent network")
	}
}

func TestNetworkByZone(t *testing.T) {
	spec := &Spec{
		Networks: []Network{
			{Name: "mgmt", Zone: "management"},
			{Name: "servers", Zone: "management"},
			{Name: "clients", Zone: "clients"},
		},
	}
	nets := spec.NetworkByZone("management")
	if len(nets) != 2 {
		t.Errorf("expected 2 networks in zone management, got %d", len(nets))
	}
}

func TestValidateAssertionRequiredFields(t *testing.T) {
	base := func() *Spec {
		return &Spec{Version: 1, Site: "test"}
	}

	cases := []struct {
		name      string
		assertion Assertion
		wantErr   string
	}{
		{
			name:      "subnet_discovery missing network",
			assertion: Assertion{Type: "subnet_discovery"},
			wantErr:   "network is required",
		},
		{
			name:      "isolation missing from",
			assertion: Assertion{Type: "isolation", To: "iot", ExpectDeny: "deny"},
			wantErr:   "from is required",
		},
		{
			name:      "isolation missing to",
			assertion: Assertion{Type: "isolation", From: "clients", ExpectDeny: "deny"},
			wantErr:   "to is required",
		},
		{
			name:      "isolation missing expect",
			assertion: Assertion{Type: "isolation", From: "clients", To: "iot"},
			wantErr:   "expect is required",
		},
		{
			name:      "vpn_route missing vpn",
			assertion: Assertion{Type: "vpn_route", Target: "10.0.0.1"},
			wantErr:   "vpn is required",
		},
		{
			name:      "vpn_route missing target",
			assertion: Assertion{Type: "vpn_route", VPN: "home-wg"},
			wantErr:   "target is required",
		},
		{
			name:      "route_check missing target",
			assertion: Assertion{Type: "route_check"},
			wantErr:   "target is required",
		},
		{
			name: "subnet_discovery min > max",
			assertion: func() Assertion {
				min, max := 10, 5
				return Assertion{Type: "subnet_discovery", Network: "net", ExpectHostsMin: &min, ExpectHostsMax: &max}
			}(),
			wantErr: "expect_hosts_min must not exceed expect_hosts_max",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := base()
			s.Assertions = []Assertion{tc.assertion}
			err := ValidateSpec(s)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("expected error containing %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
}
