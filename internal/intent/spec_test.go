package intent

import (
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
