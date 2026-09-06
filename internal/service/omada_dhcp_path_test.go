package service

import (
	"context"
	"strings"
	"testing"
)

func TestComposeDHCPPath_DumbSwitchAccessUplink(t *testing.T) {
	rep := composeDHCPPath(dhcpPathFacts{
		clientMAC: "aa:bb:cc:dd:ee:01",
		client:    &OmadaClient{MAC: "aa-bb-cc-dd-ee-01", NetworkName: "iot"},
		topo: []OmadaClientTopologyNode{
			{NodeType: "clientNode", MAC: "aa-bb-cc-dd-ee-01", SwitchMAC: "aa-bb-cc-dd-ee-10", SwitchPort: "8"},
		},
		ports: []OmadaSwitchPort{{
			Port: 8, SwitchMAC: "aa-bb-cc-dd-ee-10", NetworkMode: 1,
			NativeNetwork: "trusted", Tagged: []string{"iot", "gaming"},
		}},
		nets: []OmadaNetwork{
			{Name: "trusted", DHCPEnabled: true},
			{Name: "iot", DHCPEnabled: true, Isolated: true},
			{Name: "gaming", DHCPEnabled: true},
		},
	})
	if rep.Port == nil || rep.Port.Port != 8 {
		t.Fatalf("port = %+v, want managed port 8", rep.Port)
	}
	if !strings.Contains(rep.ManagedHop, "dumb") {
		t.Errorf("managed hop = %q, want dumb-switch note", rep.ManagedHop)
	}
	joined := strings.Join(rep.Verdicts, " | ")
	if !strings.Contains(joined, "dumb switch cannot preserve 802.1Q") {
		t.Errorf("verdicts = %v, want mixed-VLAN access uplink", rep.Verdicts)
	}
	if !strings.Contains(joined, "no lease") {
		t.Errorf("verdicts = %v, want no-lease candidate", rep.Verdicts)
	}
	if !strings.Contains(joined, "isolated") {
		t.Errorf("verdicts = %v, want isolated LAN", rep.Verdicts)
	}
}

func TestComposeDHCPPath_TrunkNativeMismatch(t *testing.T) {
	rep := composeDHCPPath(dhcpPathFacts{
		clientMAC: "aa:bb:cc:dd:ee:01",
		client:    &OmadaClient{MAC: "aa-bb-cc-dd-ee-01", NetworkName: "iot"},
		switchMAC: "aa-bb-cc-dd-ee-10",
		port:      3,
		ports: []OmadaSwitchPort{{
			Port: 3, SwitchMAC: "aa-bb-cc-dd-ee-10", NetworkMode: 0,
			NativeNetwork: "trusted", Tagged: []string{"iot"},
		}},
		nets: []OmadaNetwork{
			{Name: "trusted", DHCPEnabled: true},
			{Name: "iot", DHCPEnabled: true, DHCPGuard: true},
		},
		leases: []OmadaGatewayDHCPUser{{MAC: "aa-bb-cc-dd-ee-01", IP: "10.0.60.20", NetworkName: "iot"}},
	})
	joined := strings.Join(rep.Verdicts, " | ")
	if !strings.Contains(joined, "trunk native") {
		t.Errorf("verdicts = %v, want native≠client VLAN", rep.Verdicts)
	}
	if !strings.Contains(joined, "DHCP guard") {
		t.Errorf("verdicts = %v, want guard candidate", rep.Verdicts)
	}
	if rep.Client == nil || !rep.Client.HasLease {
		t.Errorf("client = %+v, want lease from gateway table", rep.Client)
	}
}

func TestComposeDHCPPath_RequiresSelector(t *testing.T) {
	_, err := NewOmadaService().DiagnoseDHCPPath(context.Background(), OmadaOptions{}, OmadaDHCPPathRequest{})
	if err == nil || !strings.Contains(err.Error(), "client_mac or switch_mac+port") {
		t.Errorf("err = %v, want selector required", err)
	}
}

func TestComposeDHCPPath_EmptyManagedPath(t *testing.T) {
	rep := composeDHCPPath(dhcpPathFacts{switchMAC: "aa-bb-cc-dd-ee-10", port: 1})
	if len(rep.Verdicts) != 1 || !strings.Contains(rep.Verdicts[0], "PVID") {
		t.Errorf("verdicts = %v, want unmanaged-hop PVID fallback", rep.Verdicts)
	}
}
