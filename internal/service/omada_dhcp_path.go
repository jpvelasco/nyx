package service

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
)

// OmadaDHCPPathRequest selects the crime scene: a client MAC and/or a
// managed switch port. At least one is required.
type OmadaDHCPPathRequest struct {
	ClientMAC string
	SwitchMAC string
	Port      int
}

// OmadaDHCPPathReport is the composed observe path for "link up, no lease".
type OmadaDHCPPathReport struct {
	Client     *OmadaDHCPPathClient      `json:"client,omitempty"`
	Path       []OmadaClientTopologyNode `json:"path,omitempty"`
	ManagedHop string                    `json:"managed_hop,omitempty"`
	Port       *OmadaSwitchPort          `json:"port,omitempty"`
	LANs       []OmadaNetwork            `json:"lans,omitempty"`
	Verdicts   []string                  `json:"verdicts"`
	Warnings   []string                  `json:"warnings,omitempty"`
}

// OmadaDHCPPathClient is the client side of the report.
type OmadaDHCPPathClient struct {
	MAC         string `json:"mac"`
	IP          string `json:"ip,omitempty"`
	Name        string `json:"name,omitempty"`
	NetworkName string `json:"network_name,omitempty"`
	VLANID      int    `json:"vlan_id,omitempty"`
	HasLease    bool   `json:"has_lease"`
}

type dhcpPathFacts struct {
	clientMAC string
	switchMAC string
	port      int
	client    *OmadaClient
	topo      []OmadaClientTopologyNode
	ports     []OmadaSwitchPort
	nets      []OmadaNetwork
	leases    []OmadaGatewayDHCPUser
	warnings  []string
}

// DiagnoseDHCPPath composes topology, the managed port + LAN profile,
// LAN DHCP posture, and the gateway lease table into verdict candidates.
func (s *OmadaService) DiagnoseDHCPPath(ctx context.Context, opts OmadaOptions, req OmadaDHCPPathRequest) (*OmadaDHCPPathReport, error) {
	if strings.TrimSpace(req.ClientMAC) == "" && (strings.TrimSpace(req.SwitchMAC) == "" || req.Port == 0) {
		return nil, fmt.Errorf("client_mac or switch_mac+port is required")
	}
	facts := dhcpPathFacts{clientMAC: req.ClientMAC, switchMAC: req.SwitchMAC, port: req.Port}

	if req.ClientMAC != "" {
		clients, err := s.ListClients(ctx, opts)
		if err != nil {
			facts.warnings = append(facts.warnings, "clients unavailable: "+err.Error())
		} else if c := findClient(clients, req.ClientMAC); c != nil {
			facts.client = c
		}
		topo, err := s.GetClientTopology(ctx, opts, req.ClientMAC)
		if err != nil {
			facts.warnings = append(facts.warnings, "topology unavailable: "+err.Error())
		} else {
			facts.topo = topo
		}
	}

	ports, err := s.ListSwitchPorts(ctx, opts, req.SwitchMAC)
	if err != nil {
		return nil, fmt.Errorf("listing switch ports: %w", err)
	}
	facts.ports = ports

	nets, err := s.ListNetworks(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("listing networks: %w", err)
	}
	facts.nets = nets

	if gw := firstGatewayMAC(facts.topo); gw != "" {
		leases, err := s.ListGatewayDHCPUsers(ctx, opts, gw)
		if err != nil {
			facts.warnings = append(facts.warnings, "gateway leases unavailable: "+err.Error())
		} else {
			facts.leases = leases
		}
	}

	return composeDHCPPath(facts), nil
}

func composeDHCPPath(f dhcpPathFacts) *OmadaDHCPPathReport {
	rep := &OmadaDHCPPathReport{Path: f.topo, Warnings: f.warnings, Verdicts: []string{}}
	if f.client != nil {
		rep.Client = &OmadaDHCPPathClient{
			MAC: f.client.MAC, IP: f.client.IP, Name: f.client.Name,
			NetworkName: f.client.NetworkName, VLANID: f.client.VLANID,
		}
	} else if f.clientMAC != "" {
		rep.Client = &OmadaDHCPPathClient{MAC: f.clientMAC}
	}
	if rep.Client != nil {
		if lease := leaseForMAC(f.leases, rep.Client.MAC); lease != nil {
			if rep.Client.IP == "" {
				rep.Client.IP = lease.IP
			}
			if rep.Client.NetworkName == "" {
				rep.Client.NetworkName = lease.NetworkName
			}
			rep.Client.HasLease = true
		} else if rep.Client.IP != "" {
			rep.Client.HasLease = true
		}
	}

	sw, port := crimeScenePort(f)
	if sw != "" && port != 0 {
		rep.Port = findPort(f.ports, sw, port)
		if len(f.topo) > 0 && f.switchMAC == "" {
			rep.ManagedHop = "topology stops at the managed switch port (dumb/unmanaged hops are invisible)"
		}
	}

	rep.LANs = involvedLANs(f.nets, rep.Port, rep.Client)
	rep.Verdicts = dhcpPathVerdicts(rep)
	if len(rep.Verdicts) == 0 {
		rep.Verdicts = []string{"no DHCP/VLAN mismatch candidates from the managed path; inspect the unmanaged hop's PVID if one exists"}
	}
	return rep
}

func crimeScenePort(f dhcpPathFacts) (string, int) {
	if f.switchMAC != "" && f.port != 0 {
		return f.switchMAC, f.port
	}
	for _, n := range f.topo {
		if n.SwitchMAC != "" && n.SwitchPort != "" {
			if p, err := strconv.Atoi(n.SwitchPort); err == nil {
				return n.SwitchMAC, p
			}
		}
	}
	return "", 0
}

func findPort(ports []OmadaSwitchPort, switchMAC string, port int) *OmadaSwitchPort {
	want := omadabackend.NormalizeMAC(switchMAC)
	for i := range ports {
		if omadabackend.NormalizeMAC(ports[i].SwitchMAC) == want && ports[i].Port == port {
			p := ports[i]
			return &p
		}
	}
	return nil
}

func findClient(clients []OmadaClient, mac string) *OmadaClient {
	want := omadabackend.NormalizeMAC(mac)
	for i := range clients {
		if omadabackend.NormalizeMAC(clients[i].MAC) == want {
			c := clients[i]
			return &c
		}
	}
	return nil
}

func leaseForMAC(leases []OmadaGatewayDHCPUser, mac string) *OmadaGatewayDHCPUser {
	want := omadabackend.NormalizeMAC(mac)
	for i := range leases {
		if omadabackend.NormalizeMAC(leases[i].MAC) == want {
			l := leases[i]
			return &l
		}
	}
	return nil
}

func firstGatewayMAC(topo []OmadaClientTopologyNode) string {
	for _, n := range topo {
		blob := strings.ToLower(n.NodeType + " " + n.Name + " " + n.Model)
		if strings.Contains(blob, "gateway") && n.MAC != "" {
			return n.MAC
		}
	}
	return ""
}

func involvedLANs(nets []OmadaNetwork, port *OmadaSwitchPort, client *OmadaDHCPPathClient) []OmadaNetwork {
	want := map[string]struct{}{}
	if port != nil {
		if port.NativeNetwork != "" {
			want[strings.ToLower(port.NativeNetwork)] = struct{}{}
		}
		for _, n := range port.Tagged {
			want[strings.ToLower(n)] = struct{}{}
		}
	}
	if client != nil && client.NetworkName != "" {
		want[strings.ToLower(client.NetworkName)] = struct{}{}
	}
	if len(want) == 0 {
		return nil
	}
	var out []OmadaNetwork
	for _, n := range nets {
		if _, ok := want[strings.ToLower(n.Name)]; ok {
			out = append(out, n)
		}
	}
	return out
}

func dhcpPathVerdicts(rep *OmadaDHCPPathReport) []string {
	var out []string
	if rep.Port != nil && rep.Port.NetworkMode == 1 && len(rep.Port.Tagged) > 0 {
		out = append(out, "access/untagged uplink carrying mixed tagged membership — a dumb switch cannot preserve 802.1Q; only the native VLAN's DHCP broadcasts survive")
	}
	if rep.Port != nil && rep.Port.NetworkMode == 0 && rep.Client != nil && rep.Client.NetworkName != "" &&
		!strings.EqualFold(rep.Port.NativeNetwork, rep.Client.NetworkName) {
		out = append(out, "trunk native VLAN differs from the VLAN Omada associates with the client — untagged DHCP may be mistagged")
	}
	for _, lan := range rep.LANs {
		if !lan.DHCPEnabled {
			out = append(out, "DHCP is disabled on LAN "+lan.Name)
		}
		if lan.DHCPGuard {
			out = append(out, "DHCP guard is on for LAN "+lan.Name+" — rogue/relayed offers may be dropped")
		}
		if lan.DHCPL2Relay {
			out = append(out, "DHCP L2 relay is on for LAN "+lan.Name)
		}
		if lan.Isolated {
			out = append(out, "LAN "+lan.Name+" is isolated")
		}
	}
	if rep.Client != nil && !rep.Client.HasLease {
		out = append(out, "client has no lease on the gateway table")
	}
	return out
}
