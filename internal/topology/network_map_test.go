package topology

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNetworkMapJoinsWithinLogicalSiteWithPrivateEvidence(t *testing.T) {
	sw := ResourceRef{"switch", "synthetic-switch"}
	port := ResourceRef{"port", "synthetic-switch/8"}
	seg := ResourceRef{"segment", "synthetic-network"}
	iface := ResourceRef{"interface", "synthetic-if"}
	const mac = "02:00:00:00:00:01"
	gateway := "10.0.30.1/24"
	switchFacts := ObservationSet{
		Resources: []Observation{{Ref: sw}, {Ref: port, Port: 8}, {Ref: seg, VLAN: 30}},
		Links: []LinkObservation{
			{From: sw, Relation: "port", To: MapTarget{Ref: port}, Evidence: "port inventory"},
			{From: port, Relation: "neighbor", To: MapTarget{MAC: mac}, Evidence: "LLDP"},
			{From: seg, Relation: "gateway", To: MapTarget{GatewayPrefix: gateway, VLAN: 30}, Evidence: "configured gateway", Inferred: true},
			{From: port, Relation: "native", To: MapTarget{Ref: ResourceRef{"segment", "absent"}}, Evidence: "port inventory"},
		},
	}
	firewallFacts := ObservationSet{Resources: []Observation{{Ref: iface, MAC: mac, GatewayPrefix: gateway, VLAN: 30, Name: "private-if"}}}
	sources := []MapInput{
		{Provider: "fixture", Profile: "private-fixture", LogicalSite: "shared", Facts: switchFacts},
		{Provider: "firewall", Profile: "private-firewall", LogicalSite: "shared", Facts: firewallFacts},
		{Provider: "firewall", Profile: "other", LogicalSite: "other", Facts: firewallFacts},
	}
	m := BuildNetworkMap(sources, false)
	states := map[string]string{}
	for _, l := range m.Links {
		states[l.Relation] = l.State
	}
	for k, v := range map[string]string{"port": "observed", "neighbor": "observed", "gateway": "inferred", "native": "missing"} {
		if states[k] != v {
			t.Fatalf("%s: got %v", k, m.Links)
		}
	}
	b, _ := json.Marshal(m)
	for _, value := range []string{mac, gateway, "private-", "synthetic-", "shared"} {
		if strings.Contains(string(b), value) {
			t.Errorf("default leaked %s", value)
		}
	}
	b, _ = json.Marshal(BuildNetworkMap(sources, true))
	for _, value := range []string{mac, gateway, "private-fixture", "synthetic-if"} {
		if !strings.Contains(string(b), value) {
			t.Errorf("detail omitted %s", value)
		}
	}
	sources[2].LogicalSite = "shared"
	m = BuildNetworkMap(sources, false)
	for _, l := range m.Links {
		if l.Relation == "neighbor" && (l.State != "ambiguous" || len(l.Targets) != 2) {
			t.Fatalf("duplicate endpoint %+v", l)
		}
	}
	for i := range sources {
		sources[i].LogicalSite = ""
	}
	m = BuildNetworkMap(sources, false)
	for _, l := range m.Links {
		if (l.Relation == "neighbor" || l.Relation == "gateway") && l.State != "missing" {
			t.Fatalf("unscoped join %+v", l)
		}
	}
}

func TestNetworkMapMissingAndAmbiguousIdentities(t *testing.T) {
	iface := ResourceRef{"interface", "i"}
	port := ResourceRef{"port", "p"}
	facts := ObservationSet{Resources: []Observation{{Ref: port}, {Ref: iface}, {Ref: iface}, {}}, Links: []LinkObservation{
		{From: iface, Relation: "device"},
		{From: port, To: MapTarget{Ref: iface}, Relation: "local"},
		{From: port, To: MapTarget{MAC: "chassis-name"}, Relation: "chassis"},
		{From: port, To: MapTarget{MAC: "ff:ff:ff:ff:ff:ff"}, Relation: "multicast"},
		{From: port, To: MapTarget{MAC: "00:00:00:00:00:00"}, Relation: "unspecified"},
		{From: port, To: MapTarget{GatewayPrefix: "invalid", VLAN: 30}, Relation: "invalid prefix"},
	}}
	m := BuildNetworkMap([]MapInput{{Facts: facts}}, false)
	if len(m.Sources[0].Gaps) != 2 || m.Sources[0].Gaps[0] != "link source identity" || m.Sources[0].Gaps[1] != "resource identity" || len(m.Links) != 5 {
		t.Fatalf("invalid sources %+v", m)
	}
	for _, l := range m.Links {
		want := "missing"
		if l.Relation == "local" {
			want = "ambiguous"
		}
		if l.State != want {
			t.Errorf("%s = %s, want %s", l.Relation, l.State, want)
		}
	}
}
