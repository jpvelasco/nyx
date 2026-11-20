package service

import (
	"reflect"
	"testing"

	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
	"github.com/jpvelasco/nyx/internal/topology"
)

func TestOmadaMatrixRules(t *testing.T) {
	networks := []omadabackend.Network{{ID: "n10", VLANID: 10}, {ID: "n60", VLANID: 60}}
	lanToLAN := omadabackend.ACLDirection{LANToLAN: true}
	gateway := []omadabackend.ACLRule{
		{Status: true, Policy: omadabackend.ACLPolicyDeny, SourceIDs: []string{"n10"}, DestIDs: []string{"n60"}, Direction: lanToLAN},
		{Status: true, Policy: omadabackend.ACLPolicyPermit, SourceIDs: []string{"n60"}, DestIDs: []string{"gone"}, Direction: lanToLAN},
		{Status: true, Policy: omadabackend.ACLPolicyDeny, SourceType: 2, SourceIDs: []string{"ipgroup"}, DestIDs: []string{"n10"}, Direction: lanToLAN},
		{Status: true, Policy: omadabackend.ACLPolicyDeny, SourceIDs: []string{"n10"}, Direction: omadabackend.ACLDirection{LANToWAN: true}}, // not inter-segment
		{Status: false, Policy: omadabackend.ACLPolicyDeny, SourceIDs: []string{"n10"}, DestIDs: []string{"n60"}, Direction: lanToLAN},       // disabled
	}
	switchRules := []omadabackend.ACLRule{
		{Status: true, Policy: omadabackend.ACLPolicyPermit, SourceIDs: []string{"n60"}, DestIDs: []string{"n10"}}, // switch scope has no direction
	}
	got := omadaMatrixRules(networks, gateway, switchRules)
	want := []topology.ObservedRule{
		{Provider: "omada", Allow: false, Source: topology.EndpointSet{VLANs: []int{10}}, Destination: topology.EndpointSet{VLANs: []int{60}}},
		{Provider: "omada", Allow: true, Source: topology.EndpointSet{VLANs: []int{60}}, Destination: topology.EndpointSet{Unresolved: true}},
		{Provider: "omada", Allow: false, Source: topology.EndpointSet{Unresolved: true}, Destination: topology.EndpointSet{VLANs: []int{10}}},
		{Provider: "omada", Allow: true, Source: topology.EndpointSet{VLANs: []int{60}}, Destination: topology.EndpointSet{VLANs: []int{10}}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("omadaMatrixRules =\n%+v\nwant\n%+v", got, want)
	}
}

func TestOpnsenseMatrixRules(t *testing.T) {
	ifaces := []OpnsenseInterface{
		{Name: "opt1", Device: "vlan01"},
		{Name: "opt6", Device: "vlan06"},
		{Name: "lan", Device: "igb1"}, // untagged: no VLAN segment
	}
	vlans := []OpnsenseVLAN{{Tag: 10, Device: "vlan01"}, {Tag: 60, Device: "vlan06"}}
	subnets := []topology.SegmentSubnet{{VLAN: 60, Provider: "opnsense", Gateway: "10.0.60.1/24"}}
	rules := []OpnsenseFirewallRule{
		{Enabled: true, Action: "block", Interfaces: []string{"opt6"}, Source: "opt6", Destination: "opt1"},
		{Enabled: true, Action: "pass", Interfaces: []string{"opt1"}, Source: "any", Destination: "10.0.60.0/24"}, // any on one iface = that segment
		{Enabled: true, Action: "pass", Interfaces: []string{"opt1", "opt6"}, Source: "any", Destination: "opt1"}, // any on many ifaces = wildcard
		{Enabled: true, Action: "reject", Interfaces: []string{"opt1"}, Source: "opt1", Destination: "any"},
		{Enabled: true, Action: "pass", Interfaces: []string{"opt1"}, Source: "opt1", Destination: "trusted_hosts"}, // alias
		{Enabled: true, Action: "pass", Interfaces: []string{"lan"}, Source: "lan", Destination: "opt1"},            // untagged lan
		{Enabled: true, Action: "pass", Interfaces: []string{"opt1"}, Source: "opt1", Destination: "opt1ip"},        // the firewall itself
		{Enabled: false, Disabled: true, Action: "block", Interfaces: []string{"opt1"}, Source: "opt1", Destination: "opt6"},
	}
	set := func(v ...int) topology.EndpointSet { return topology.EndpointSet{VLANs: v} }
	anyEnd, unresolved := topology.EndpointSet{Any: true}, topology.EndpointSet{Unresolved: true}
	want := []topology.ObservedRule{
		{Provider: "opnsense", Allow: false, Source: set(60), Destination: set(10)},
		{Provider: "opnsense", Allow: true, Source: set(10), Destination: set(60)},
		{Provider: "opnsense", Allow: true, Source: anyEnd, Destination: set(10)},
		{Provider: "opnsense", Allow: false, Source: set(10), Destination: anyEnd},
		{Provider: "opnsense", Allow: true, Source: set(10), Destination: unresolved},
		{Provider: "opnsense", Allow: true, Source: unresolved, Destination: set(10)},
		{Provider: "opnsense", Allow: true, Source: set(10), Destination: unresolved},
	}
	if got := opnsenseMatrixRules(rules, ifaces, vlans, subnets); !reflect.DeepEqual(got, want) {
		t.Fatalf("opnsenseMatrixRules =\n%+v\nwant\n%+v", got, want)
	}
}
