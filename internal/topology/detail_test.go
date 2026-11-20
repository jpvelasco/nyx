package topology

import (
	"reflect"
	"testing"
)

func TestAttachDetail(t *testing.T) {
	segments := []FingerprintSegment{
		{VLAN: 10, Gateway: ProviderOmada, ObservedBy: []string{ProviderOmada, ProviderOpnsense}},
		{VLAN: 60, ObservedBy: []string{ProviderOpnsense}},
		{VLAN: 99}, // no subnet observed anywhere
	}
	subnets := []SegmentSubnet{
		{VLAN: 10, Provider: ProviderOpnsense, Gateway: "10.0.10.2/24"}, // non-serving view
		{VLAN: 10, Provider: ProviderOmada, Gateway: "10.0.10.1/24"},    // serving provider wins
		{VLAN: 60, Provider: ProviderOpnsense, Gateway: "10.0.60.1/24"},
	}
	hosts := []HostSighting{
		{Address: "10.0.10.1", Hostname: "gw", Source: ProviderOmada}, // the gateway itself
		{Address: "10.0.10.30", Hostname: "desk", Source: ProviderOmada},
		{Address: "10.0.10.20", Source: ProviderOpnsense},
		{Address: "10.0.10.30", Hostname: "desk", Source: ProviderOpnsense}, // duplicate address
		{Address: "10.0.20.5", Source: ProviderOmada},                       // outside every segment
		{Address: "not-an-ip", Source: ProviderOmada},
		{Address: "10.0.60.7", Hostname: "cam", Source: ProviderOpnsense},
	}
	got := AttachDetail(segments, subnets, hosts, 5)

	want := []FingerprintSegment{
		{VLAN: 10, Gateway: ProviderOmada, ObservedBy: []string{ProviderOmada, ProviderOpnsense}, Detail: &SegmentDetail{
			CIDR: "10.0.10.0/24", GatewayAddress: "10.0.10.1",
			ProbeCandidates: []ProbeCandidate{
				{Address: "10.0.10.20", Source: ProviderOpnsense},
				{Address: "10.0.10.30", Hostname: "desk", Source: ProviderOmada},
			},
		}},
		{VLAN: 60, ObservedBy: []string{ProviderOpnsense}, Detail: &SegmentDetail{
			CIDR: "10.0.60.0/24", GatewayAddress: "10.0.60.1",
			ProbeCandidates: []ProbeCandidate{{Address: "10.0.60.7", Hostname: "cam", Source: ProviderOpnsense}},
		}},
		{VLAN: 99},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("AttachDetail =\n%+v\nwant\n%+v", got, want)
	}
}

func TestAttachDetailCapsCandidates(t *testing.T) {
	segments := []FingerprintSegment{{VLAN: 40, Gateway: ProviderOpnsense}}
	subnets := []SegmentSubnet{{VLAN: 40, Provider: ProviderOpnsense, Gateway: "10.0.40.1/24"}}
	var hosts []HostSighting
	for _, a := range []string{"10.0.40.9", "10.0.40.3", "10.0.40.12", "10.0.40.4", "10.0.40.5", "10.0.40.6", "10.0.40.7"} {
		hosts = append(hosts, HostSighting{Address: a, Source: ProviderOpnsense})
	}
	got := AttachDetail(segments, subnets, hosts, 5)[0].Detail.ProbeCandidates
	var addrs []string
	for _, c := range got {
		addrs = append(addrs, c.Address)
	}
	// Numeric address order, not string order, then capped.
	want := []string{"10.0.40.3", "10.0.40.4", "10.0.40.5", "10.0.40.6", "10.0.40.7"}
	if !reflect.DeepEqual(addrs, want) {
		t.Fatalf("candidates = %v, want %v", addrs, want)
	}
}

func TestAttachDetailIgnoresUnparseableSubnet(t *testing.T) {
	segments := []FingerprintSegment{{VLAN: 10}}
	got := AttachDetail(segments, []SegmentSubnet{{VLAN: 10, Provider: ProviderOmada, Gateway: "dynamic"}}, nil, 5)
	if got[0].Detail != nil {
		t.Fatalf("detail = %+v, want nil for an unparseable subnet", got[0].Detail)
	}
}

func TestAttachDetailSanitizesHostnames(t *testing.T) {
	segments := []FingerprintSegment{{VLAN: 60, Gateway: ProviderOpnsense}}
	subnets := []SegmentSubnet{{VLAN: 60, Provider: ProviderOpnsense, Gateway: "10.0.60.1/24"}}
	hosts := []HostSighting{{Address: "10.0.60.7", Hostname: "\x1b[2J\x1b]0;owned\acam\u202e", Source: ProviderOpnsense}}
	got := AttachDetail(segments, subnets, hosts, 5)[0].Detail.ProbeCandidates[0].Hostname
	if want := "[2J]0;ownedcam"; got != want {
		t.Fatalf("hostname = %q, want %q (control and format runes stripped)", got, want)
	}
}
