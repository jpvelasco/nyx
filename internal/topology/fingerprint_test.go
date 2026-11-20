package topology

import (
	"reflect"
	"testing"
)

func TestFingerprintRole(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		device               DeviceReport
		serving, bridge, nat bool
		want                 string
	}{
		{"edge", DeviceReport{OnPath: true, Role: RoleNatRouter}, true, false, true, "enforcer"},
		{"bridge", DeviceReport{Role: RoleBridge}, false, true, false, "observer"},
		{"no bridge evidence", DeviceReport{Role: RoleBridge}, false, false, false, "unknown"},
		{"destination-only NAT", DeviceReport{OnPath: true, Role: RoleNatRouter}, true, false, false, "unknown"},
		{"off path", DeviceReport{Role: RoleNatRouter}, true, false, true, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			role, guide := FingerprintRole(tc.device, tc.serving, tc.bridge, tc.nat)
			if role != tc.want || (guide == "") != (role == "unknown") {
				t.Errorf("role = %q, guide = %q; want %q", role, guide, tc.want)
			}
		})
	}
}

func TestMergeSegments(t *testing.T) {
	obs := []SegmentObservation{
		{VLAN: 60, Provider: ProviderOpnsense},
		{VLAN: 10, Provider: ProviderOmada, Serves: true},
		{VLAN: 10, Provider: ProviderOpnsense},
		{VLAN: 20, Provider: ProviderOmada},
		{VLAN: 40, Provider: ProviderOmada, Serves: true},
		{VLAN: 40, Provider: ProviderOpnsense, Serves: true},
		{VLAN: 60, Provider: ProviderOpnsense}, // duplicate tag from one provider
	}
	segments, warnings := MergeSegments(obs)

	want := []FingerprintSegment{
		{VLAN: 10, Gateway: ProviderOmada, ObservedBy: []string{ProviderOmada, ProviderOpnsense}},
		{VLAN: 20, ObservedBy: []string{ProviderOmada}},
		{VLAN: 40, Gateway: ProviderOmada, ObservedBy: []string{ProviderOmada, ProviderOpnsense}},
		{VLAN: 60, ObservedBy: []string{ProviderOpnsense}},
	}
	if !reflect.DeepEqual(segments, want) {
		t.Fatalf("segments = %+v\nwant %+v", segments, want)
	}
	wantWarnings := []string{
		"VLAN 20 observed by omada; no inventory serves its gateway",
		"VLAN 40 gateway observed on both omada and opnsense",
		"VLAN 60 observed by opnsense; no inventory serves its gateway",
	}
	if !reflect.DeepEqual(warnings, wantWarnings) {
		t.Fatalf("warnings = %q\nwant %q", warnings, wantWarnings)
	}
}

func TestMergeSegmentsFullCoverage(t *testing.T) {
	segments, warnings := MergeSegments([]SegmentObservation{
		{VLAN: 10, Provider: ProviderOmada, Serves: true},
		{VLAN: 11, Provider: ProviderOpnsense, Serves: true},
	})
	if len(segments) != 2 || len(warnings) != 0 {
		t.Fatalf("segments = %+v, warnings = %q", segments, warnings)
	}
}

func TestClassifyNextHop(t *testing.T) {
	for _, tc := range []struct {
		name     string
		gateways []string
		want     string
	}{
		{"public", []string{"203.0.113.1"}, NextHopInternet},
		{"carrier-grade NAT", []string{"100.64.0.1"}, NextHopInternet},
		{"private router", []string{"10.0.11.1"}, NextHopUpstreamRouter},
		{"public wins over private", []string{"10.0.11.1", "198.51.100.1"}, NextHopInternet},
		{"link-local v6 is ambiguous", []string{"fe80::1"}, NextHopUnknown},
		{"ula", []string{"fd00::1"}, NextHopUpstreamRouter},
		{"none", nil, NextHopUnknown},
		{"unparseable", []string{"dynamic"}, NextHopUnknown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyNextHop(tc.gateways); got != tc.want {
				t.Errorf("ClassifyNextHop(%q) = %q, want %q", tc.gateways, got, tc.want)
			}
		})
	}
}

func TestSelectEdge(t *testing.T) {
	omada := FingerprintDevice{Provider: ProviderOmada}
	downstream := FingerprintDevice{Provider: ProviderOpnsense, ManagedUpstream: ProviderOmada}
	standalone := FingerprintDevice{Provider: ProviderOpnsense}
	for _, tc := range []struct {
		name    string
		devices []FingerprintDevice
		nextHop map[string]string
		want    *FingerprintEdge
	}{
		{"opnsense behind omada: omada is the edge", []FingerprintDevice{omada, downstream},
			map[string]string{ProviderOpnsense: NextHopUpstreamRouter},
			&FingerprintEdge{Provider: ProviderOmada, NextHop: NextHopUnknown}},
		{"observed next hop wins", []FingerprintDevice{omada, standalone},
			map[string]string{ProviderOpnsense: NextHopInternet},
			&FingerprintEdge{Provider: ProviderOpnsense, NextHop: NextHopInternet}},
		{"branch", []FingerprintDevice{standalone},
			map[string]string{ProviderOpnsense: NextHopUpstreamRouter},
			&FingerprintEdge{Provider: ProviderOpnsense, NextHop: NextHopUpstreamRouter}},
		{"omada only", []FingerprintDevice{omada}, nil,
			&FingerprintEdge{Provider: ProviderOmada, NextHop: NextHopUnknown}},
		{"no devices", nil, nil, &FingerprintEdge{NextHop: NextHopUnknown}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := SelectEdge(tc.devices, tc.nextHop); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("SelectEdge = %+v, want %+v", got, tc.want)
			}
		})
	}
}
