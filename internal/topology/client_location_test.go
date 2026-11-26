package topology

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestClientLocationEvidence(t *testing.T) {
	port := ResourceRef{"port", "switch/8"}
	ap := ResourceRef{"ap", "ap-private"}
	seg := ResourceRef{"segment", "gaming"}
	inputs := []MapInput{{Provider: "fixture", Facts: ObservationSet{Resources: []Observation{{Ref: port, Port: 8}, {Ref: ap}, {Ref: seg, VLAN: 30}}, Links: []LinkObservation{{From: ap, To: MapTarget{Ref: port}, Relation: "uplink"}, {From: port, To: MapTarget{Ref: seg}, Relation: "native"}}}}}
	wifi := ClientObservation{Kind: "association", Status: "current", Attachment: ap, Device: "private"}
	wired := ClientObservation{Kind: "association", Status: "current", Attachment: port, Port: 8}
	lease := ClientObservation{Kind: "DHCP lease", Status: "cached", Address: "192.0.2.10"}
	historical := ClientObservation{Kind: "history", Status: "historical", Attachment: ap}
	for _, tc := range []struct {
		name   string
		rows   []ClientObservation
		status string
		path   int
	}{
		{"wireless", []ClientObservation{wifi, lease}, "located", 2},
		{"wired after roaming", []ClientObservation{wired, historical}, "located", 2},
		{"neighbor only", []ClientObservation{{Kind: "NDP", Status: "cached"}}, "unconfirmed", 0},
		{"lease only", []ClientObservation{lease}, "unconfirmed", 0},
		{"contradictory associations", []ClientObservation{wired, wifi}, "ambiguous", 3},
		{"absent", nil, "unconfirmed", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := LocateClient([]ClientMapInput{{MapInput: inputs[0], Evidence: tc.rows}}, false)
			if got.Status != tc.status || len(got.Path.Resources) != tc.path || got.DownstreamPort != "unknown" {
				t.Fatalf("%+v", got)
			}
			for _, l := range got.Path.Links {
				if (l.Relation == "native" || l.Relation == "tagged") && l.State != "inferred" {
					t.Fatal("configured port membership cannot establish client VLAN")
				}
			}
			b, _ := json.Marshal(got)
			if strings.Contains(string(b), "private") || strings.Contains(string(b), "192.0.2.") {
				t.Error("default output leaked private evidence")
			}
		})
	}
}

func TestClientOnTrunkHasCandidateVLANs(t *testing.T) {
	port := ResourceRef{"port", "switch/8"}
	native, tag := ResourceRef{"segment", "management"}, ResourceRef{"segment", "gaming"}
	in := ClientMapInput{MapInput: MapInput{Provider: "fixture", Facts: ObservationSet{Resources: []Observation{{Ref: port, Port: 8}, {Ref: native, VLAN: 11}, {Ref: tag, VLAN: 30}}, Links: []LinkObservation{{From: port, Relation: "native", To: MapTarget{Ref: native}}, {From: port, Relation: "tagged", To: MapTarget{Ref: tag}}}}}, Evidence: []ClientObservation{{Kind: "association", Status: "current", Attachment: port}}}
	result := LocateClient([]ClientMapInput{in}, false)
	if result.Status != "located" || len(result.Path.Links) != 2 {
		t.Fatal(result)
	}
	for _, link := range result.Path.Links {
		if link.State != "inferred" || link.Evidence != "configured port membership" {
			t.Fatal("reported client VLAN without association evidence", link)
		}
	}
}
