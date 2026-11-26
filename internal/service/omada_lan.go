package service

import (
	"context"
	"fmt"
	"strings"

	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
)

// OmadaGatewayDHCPUser is one row of the per-gateway DHCP lease table.
type OmadaGatewayDHCPUser struct {
	IP            string `json:"ip"`
	MAC           string `json:"mac"`
	Name          string `json:"name,omitempty"`
	NetworkName   string `json:"network_name,omitempty"`
	LeftLeaseSec  int    `json:"left_lease_sec,omitempty"`
	LeftLeaseTime string `json:"left_lease_time,omitempty"`
}

// OmadaDHCPServerInfo is the per-network DHCP pool panel (available IPs).
type OmadaDHCPServerInfo struct {
	NetworkID    string `json:"network_id"`
	AvailableIPs int    `json:"available_ips"`
	TotalIPs     int    `json:"total_ips,omitempty"`
	Start        string `json:"start,omitempty"`
	End          string `json:"end,omitempty"`
}

// OmadaDHCPSnoopStatus is the site-wide DHCP snooping switch.
type OmadaDHCPSnoopStatus struct {
	Enabled bool `json:"enabled"`
}

// OmadaDHCPSnoopRule is one DHCP snooping rule.
type OmadaDHCPSnoopRule struct {
	ID      string `json:"id,omitempty"`
	Name    string `json:"name,omitempty"`
	Enabled bool   `json:"enabled"`
}

// OmadaLANMulticastRule is one multicast-filter row.
type OmadaLANMulticastRule struct {
	ID      string `json:"id,omitempty"`
	Name    string `json:"name,omitempty"`
	Enabled bool   `json:"enabled"`
}

// OmadaClientTopologyNode is one hop in a client's uplink chain.
type OmadaClientTopologyNode struct {
	NodeType   string `json:"node_type"`
	MAC        string `json:"mac,omitempty"`
	Name       string `json:"name,omitempty"`
	Model      string `json:"model,omitempty"`
	ClientType string `json:"client_type,omitempty"`
	SwitchMAC  string `json:"switch_mac,omitempty"`
	SwitchName string `json:"switch_name,omitempty"`
	SwitchPort string `json:"switch_port,omitempty"`
	APMAC      string `json:"ap_mac,omitempty"`
	APName     string `json:"ap_name,omitempty"`
	LinkSpeed  int    `json:"link_speed,omitempty"`
	RSSI       int    `json:"rssi,omitempty"`
}

// ListGatewayDHCPUsers returns the fresher per-gateway DHCP lease table.
func (s *OmadaService) ListGatewayDHCPUsers(ctx context.Context, opts OmadaOptions, gatewayMAC string) ([]OmadaGatewayDHCPUser, error) {
	if strings.TrimSpace(gatewayMAC) == "" {
		return nil, fmt.Errorf("gateway_mac is required")
	}
	client, site, err := s.session(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer client.Logout(ctx) //nolint:errcheck

	rows, err := client.GetGatewayDHCPUsers(ctx, site.EffectiveID(), gatewayMAC)
	if err != nil {
		return nil, fmt.Errorf("fetching gateway DHCP users: %w", err)
	}
	out := make([]OmadaGatewayDHCPUser, 0, len(rows))
	for _, r := range rows {
		out = append(out, OmadaGatewayDHCPUser{
			IP:            r.IP,
			MAC:           r.MAC,
			Name:          r.Name,
			NetworkName:   r.NetworkName,
			LeftLeaseSec:  r.LeftLeaseSec,
			LeftLeaseTime: r.LeftLeaseTime,
		})
	}
	return out, nil
}

// GetDHCPServerInfo returns the pool panel (available-IP count) for one LAN.
func (s *OmadaService) GetDHCPServerInfo(ctx context.Context, opts OmadaOptions, networkID string) (*OmadaDHCPServerInfo, error) {
	if strings.TrimSpace(networkID) == "" {
		return nil, fmt.Errorf("network_id is required")
	}
	return withSession(s, ctx, opts, func(client *omadabackend.Client, siteID string) (*OmadaDHCPServerInfo, error) {
		info, err := client.GetDHCPServerInfo(ctx, siteID, networkID)
		if err != nil {
			return nil, fmt.Errorf("fetching DHCP server info: %w", err)
		}
		return &OmadaDHCPServerInfo{
			NetworkID: networkID, AvailableIPs: info.AvailableIPs, TotalIPs: info.TotalIPs,
			Start: info.Start, End: info.End,
		}, nil
	})
}

// GetDHCPSnoopStatus returns the site-wide DHCP snooping switch.
func (s *OmadaService) GetDHCPSnoopStatus(ctx context.Context, opts OmadaOptions) (*OmadaDHCPSnoopStatus, error) {
	return withSession(s, ctx, opts, func(client *omadabackend.Client, siteID string) (*OmadaDHCPSnoopStatus, error) {
		st, err := client.GetDHCPSnoopStatus(ctx, siteID)
		if err != nil {
			return nil, fmt.Errorf("fetching DHCP snooping status: %w", err)
		}
		return &OmadaDHCPSnoopStatus{Enabled: st.Enabled}, nil
	})
}

// ListDHCPSnoops returns the site's DHCP snooping rules.
func (s *OmadaService) ListDHCPSnoops(ctx context.Context, opts OmadaOptions) ([]OmadaDHCPSnoopRule, error) {
	return withSession(s, ctx, opts, func(client *omadabackend.Client, siteID string) ([]OmadaDHCPSnoopRule, error) {
		rows, err := client.GetDHCPSnoops(ctx, siteID)
		if err != nil {
			return nil, fmt.Errorf("fetching DHCP snooping rules: %w", err)
		}
		out := make([]OmadaDHCPSnoopRule, 0, len(rows))
		for _, r := range rows {
			out = append(out, OmadaDHCPSnoopRule{ID: r.ID, Name: r.Name, Enabled: r.Enabled})
		}
		return out, nil
	})
}

// ListLANMulticasts returns the site's multicast-filter / snooping-tab rules.
func (s *OmadaService) ListLANMulticasts(ctx context.Context, opts OmadaOptions) ([]OmadaLANMulticastRule, error) {
	return withSession(s, ctx, opts, func(client *omadabackend.Client, siteID string) ([]OmadaLANMulticastRule, error) {
		rows, err := client.GetLANMulticasts(ctx, siteID)
		if err != nil {
			return nil, fmt.Errorf("fetching LAN multicast rules: %w", err)
		}
		out := make([]OmadaLANMulticastRule, 0, len(rows))
		for _, r := range rows {
			out = append(out, OmadaLANMulticastRule{ID: r.ID, Name: r.Name, Enabled: r.Enabled})
		}
		return out, nil
	})
}

// GetClientTopology returns the client's uplink chain (POST-only Open API).
// A dumb switch does not appear; the last managed port is the crime scene.
func (s *OmadaService) GetClientTopology(ctx context.Context, opts OmadaOptions, clientMAC string) ([]OmadaClientTopologyNode, error) {
	if strings.TrimSpace(clientMAC) == "" {
		return nil, fmt.Errorf("client_mac is required")
	}
	client, site, err := s.session(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer client.Logout(ctx) //nolint:errcheck

	rows, err := client.GetClientTopology(ctx, site.EffectiveID(), clientMAC)
	if err != nil {
		return nil, fmt.Errorf("fetching client topology: %w", err)
	}
	out := make([]OmadaClientTopologyNode, 0, len(rows))
	for _, r := range rows {
		out = append(out, OmadaClientTopologyNode{
			NodeType:   r.NodeType,
			MAC:        r.MAC,
			Name:       r.Name,
			Model:      r.Model,
			ClientType: r.ClientType,
			SwitchMAC:  r.SwitchMAC,
			SwitchName: r.SwitchName,
			SwitchPort: r.SwitchPort,
			APMAC:      r.APMAC,
			APName:     r.APName,
			LinkSpeed:  r.LinkSpeed,
			RSSI:       r.RSSI,
		})
	}
	return out, nil
}

// OmadaLANRequest is a plan/apply LAN mutation.
type OmadaLANRequest struct {
	CreateOnly    bool // Preserve an existing resource if a composed create plan becomes an update.
	Name          string
	VLAN          int
	GatewaySubnet string
	Isolated      bool
	DHCPEnabled   bool
	DHCPStart     string
	DHCPEnd       string
	LeaseTime     int
	DHCPDNS       string
	DHCPL2Relay   bool
	DHCPGuard     bool
	IGMPSnoop     bool
	MLDSnoop      bool
	Delete        bool
}

// OmadaLANPlan previews a LAN create/update/delete.
type OmadaLANPlan struct {
	Action  string `json:"action"` // create / update / delete / unchanged
	Network string `json:"network"`
	ID      string `json:"id,omitempty"`
	Before  string `json:"before,omitempty"`
	After   string `json:"after,omitempty"`
}

// OmadaLANApplyResult is the apply outcome.
type OmadaLANApplyResult struct {
	Outcome string `json:"outcome"`
	ID      string `json:"id,omitempty"`
	DryRun  bool   `json:"dry_run"`
	Before  string `json:"before,omitempty"`
	After   string `json:"after,omitempty"`
}

func (req OmadaLANRequest) write() omadabackend.LANWrite {
	return omadabackend.LANWrite{
		Name:              req.Name,
		Purpose:           0,
		VLANID:            req.VLAN,
		GatewaySubnet:     req.GatewaySubnet,
		Isolation:         req.Isolated,
		IGMPSnoopEnable:   req.IGMPSnoop,
		MLDSnoopEnable:    req.MLDSnoop,
		DHCPL2RelayEnable: req.DHCPL2Relay,
		DHCPGuard:         req.DHCPGuard,
		DHCPSettings: omadabackend.DHCPSettingsVO{
			Enable:      req.DHCPEnabled,
			IPAddrStart: req.DHCPStart,
			IPAddrEnd:   req.DHCPEnd,
			LeaseTime:   req.LeaseTime,
			DHCPNS:      req.DHCPDNS,
		},
	}
}

// PlanLAN previews creating, updating, or deleting a site LAN.
func (s *OmadaService) PlanLAN(ctx context.Context, opts OmadaOptions, req OmadaLANRequest) (*OmadaLANPlan, error) {
	if req.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	client, site, err := s.session(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer client.Logout(ctx) //nolint:errcheck
	nets, err := client.GetNetworks(ctx, site.EffectiveID())
	if err != nil {
		return nil, err
	}
	if req.CreateOnly {
		matches := 0
		for _, row := range nets {
			if row.VLANID != req.VLAN && !strings.EqualFold(row.Name, req.Name) {
				continue
			}
			matches++
			if matches > 1 || !strings.EqualFold(row.Name, req.Name) || row.VLANID != req.VLAN || !strings.EqualFold(row.Purpose, "vlan") || !row.DHCPKnown || row.DHCPEnabled || row.GatewaySubnet != "" || row.Primary {
				return nil, fmt.Errorf("VLAN tag or role is already owned by another network")
			}
		}
	}
	cur, ok := omadabackend.FindNetwork(nets, req.Name)
	plan := &OmadaLANPlan{Network: req.Name}
	if req.Delete {
		if !ok {
			plan.Action = "unchanged"
			return plan, nil
		}
		plan.Action = "delete"
		plan.ID = cur.ID
		return plan, nil
	}
	w := req.write()
	if !ok {
		plan.Action = "create"
		return plan, nil
	}
	plan.ID = cur.ID
	if omadabackend.LANMatchesWrite(cur, w) {
		plan.Action = "unchanged"
		return plan, nil
	}
	plan.Action = "update"
	return plan, nil
}

// ApplyLAN creates, updates, or deletes a site LAN. Dry-run by default
// at the MCP layer.
func (s *OmadaService) ApplyLAN(ctx context.Context, opts OmadaOptions, req OmadaLANRequest, dryRun bool) (*OmadaLANApplyResult, error) {
	plan, err := s.PlanLAN(ctx, opts, req)
	if err != nil {
		return nil, err
	}
	res := &OmadaLANApplyResult{Outcome: plan.Action, ID: plan.ID, DryRun: dryRun}
	if err := preserveExisting(req.CreateOnly, plan.Action); err != nil {
		return nil, err
	}
	if dryRun || plan.Action == "unchanged" {
		return res, nil
	}
	client, site, err := s.session(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer client.Logout(ctx) //nolint:errcheck
	siteID := site.EffectiveID()
	switch plan.Action {
	case "create":
		id, err := client.CreateLANNetwork(ctx, siteID, req.write())
		if err != nil {
			return nil, err
		}
		res.ID = id
		res.Outcome = "created"
	case "update":
		if err := client.UpdateLANNetwork(ctx, siteID, plan.ID, req.write()); err != nil {
			return nil, err
		}
		res.Outcome = "updated"
	case "delete":
		if err := client.DeleteLANNetwork(ctx, siteID, plan.ID); err != nil {
			return nil, err
		}
		res.Outcome = "deleted"
	}
	return res, nil
}
