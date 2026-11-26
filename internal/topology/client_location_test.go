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
			b, _ := json.Marshal(got)
			if strings.Contains(string(b), "private") || strings.Contains(string(b), "192.0.2.") {
				t.Error("default output leaked private evidence")
			}
		})
	}
}
