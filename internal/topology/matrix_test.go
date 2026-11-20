package topology

import (
	"reflect"
	"testing"
)

func vlans(ids ...int) EndpointSet { return EndpointSet{VLANs: ids} }

func TestBuildMatrix(t *testing.T) {
	rules := []ObservedRule{
		{Provider: ProviderOmada, Allow: false, Source: vlans(10), Destination: vlans(60)},
		{Provider: ProviderOmada, Allow: true, Source: vlans(10), Destination: vlans(40, 60)},
		{Provider: ProviderOpnsense, Allow: false, Source: vlans(60), Destination: vlans(10)},
		{Provider: ProviderOpnsense, Allow: true, Source: vlans(60), Destination: EndpointSet{Any: true}},
		{Provider: ProviderOmada, Allow: false, Source: vlans(10), Destination: EndpointSet{Unresolved: true}},
		{Provider: ProviderOpnsense, Allow: true, Source: EndpointSet{Unresolved: true}, Destination: EndpointSet{Any: true}},
		{Provider: ProviderOmada, Allow: true, Source: vlans(10), Destination: vlans(10)}, // same segment: not a pair
		{Provider: ProviderOmada, Allow: true, Source: vlans(10), Destination: vlans(99)}, // unobserved VLAN
	}
	m := BuildMatrix([]int{60, 10, 40}, rules)

	wantPairs := []MatrixPair{
		{From: 10, To: 40, PairSpecific: true, Rules: []PairCount{{Provider: ProviderOmada, Allow: 1}}},
		{From: 10, To: 60, PairSpecific: true, Rules: []PairCount{{Provider: ProviderOmada, Allow: 1, Deny: 1}}},
		{From: 40, To: 10},
		{From: 40, To: 60},
		{From: 60, To: 10, PairSpecific: true, Rules: []PairCount{{Provider: ProviderOpnsense, Deny: 1}}},
		{From: 60, To: 40},
	}
	if !reflect.DeepEqual(m.Pairs, wantPairs) {
		t.Fatalf("pairs =\n%+v\nwant\n%+v", m.Pairs, wantPairs)
	}
	wantProviders := []MatrixProviderTotals{
		{Provider: ProviderOmada, Unresolved: 2},
		{Provider: ProviderOpnsense, Wildcard: 1, Unresolved: 1},
	}
	if !reflect.DeepEqual(m.Providers, wantProviders) {
		t.Fatalf("providers = %+v, want %+v", m.Providers, wantProviders)
	}
	want := [][2]int{{40, 10}, {40, 60}, {60, 40}}
	if got := m.Uncovered(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Uncovered = %v, want %v", got, want)
	}
}

func TestBuildMatrixSingleSegment(t *testing.T) {
	m := BuildMatrix([]int{10}, nil)
	if len(m.Pairs) != 0 || len(m.Uncovered()) != 0 {
		t.Fatalf("matrix = %+v", m)
	}
}
