package service

import (
	"context"
	"fmt"

	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
	"github.com/jpvelasco/nyx/internal/intent"
)

// OmadaClient is a connected client in a flat, agent-friendly shape. The
// controller reports thin rows (MAC, name, type); IP, network name, and VLAN
// id are filled in from the site's DHCP user list on a best-effort basis.
type OmadaClient struct {
	MAC         string `json:"mac"`
	IP          string `json:"ip"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	NetworkName string `json:"network_name"`
	VLANID      int    `json:"vlan_id"`
}

// ListClients returns the connected clients of the selected site.
func (s *OmadaService) ListClients(ctx context.Context, opts OmadaOptions) ([]OmadaClient, error) {
	client, site, err := s.session(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer client.Logout(ctx) //nolint:errcheck

	siteID := site.EffectiveID()
	clients, err := client.GetClients(ctx, siteID)
	if err != nil {
		return nil, fmt.Errorf("fetching clients: %w", err)
	}
	// The thin client wire has no IP or network name. Enrichment from the
	// DHCP user list is best-effort: on a failure the clients are returned
	// with the wire fields as-is.
	var nets []omadabackend.Network
	if netList, nerr := client.GetNetworks(ctx, siteID); nerr == nil {
		nets = netList
	}
	// Best-effort: on a fetch or decode failure the clients keep their
	// thin wire fields.
	_ = client.EnrichFromDHCP(ctx, siteID, clients, nets)
	out := make([]OmadaClient, 0, len(clients))
	for _, c := range clients {
		out = append(out, OmadaClient{
			MAC:         c.MAC,
			IP:          c.IP,
			Name:        c.Name,
			Type:        c.Type,
			NetworkName: c.NetworkName,
			VLANID:      c.VLANID,
		})
	}
	return out, nil
}

// OmadaInventory is the site's point-in-time observation in a flat,
// agent-friendly shape: devices, networks with gateway bindings, ACL scope
// states, and the active client count.
type OmadaInventory struct {
	Site               string                `json:"site"`
	ControllerVersion  string                `json:"controller_version"`
	ControllerCategory string                `json:"controller_category,omitempty"`
	Devices            []serviceDevice       `json:"devices"`
	NetworkGateways    map[string]string     `json:"network_gateways,omitempty"`
	ACLScopes          []serviceACLScope     `json:"acl_scopes,omitempty"`
	MDNS               *intent.MDNSInventory `json:"mdns,omitempty"`
	ClientCount        int                   `json:"client_count"`
	Warnings           []string              `json:"warnings,omitempty"`
}

// serviceDevice is one managed device (gateway, switch, or AP).
type serviceDevice struct {
	Type     string   `json:"type"`
	Name     string   `json:"name"`
	Model    string   `json:"model"`
	IP       string   `json:"ip,omitempty"`
	Firmware string   `json:"firmware,omitempty"`
	Upgrade  bool     `json:"upgrade_available,omitempty"`
	Networks []string `json:"networks,omitempty"`

	FirmwareStatus   string `json:"firmware_status,omitempty"`
	FirmwareAdvisory string `json:"firmware_advisory,omitempty"`
}

// serviceACLScope is the rule count of one ACL scope (gateway | switch).
// The Open API has no scope enable/disable flag.
type serviceACLScope struct {
	Scope     string `json:"scope"`
	RuleCount int    `json:"rule_count"`
}

// Inventory returns the site's device/network/ACL-scope/client observation.
// It is read-only: no controller state is mutated.
func (s *OmadaService) Inventory(ctx context.Context, opts OmadaOptions) (*OmadaInventory, error) {
	client, site, err := s.session(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer client.Logout(ctx) //nolint:errcheck

	snap, err := client.FetchInventory(ctx, site.EffectiveID())
	if err != nil {
		return nil, err
	}
	inv := &OmadaInventory{
		Site:               site.Name,
		ControllerVersion:  snap.ControllerVersion,
		ControllerCategory: snap.ControllerCategory,
		Devices:            []serviceDevice{},
		ACLScopes:          []serviceACLScope{},
		ClientCount:        len(snap.Clients),
		MDNS:               snap.MDNS,
		Warnings:           snap.Warnings,
		NetworkGateways:    map[string]string{},
	}
	specInv := omadabackend.BuildSpecInventory(snap)
	inv.NetworkGateways = specInv.NetworkGateways
	for _, d := range specInv.Devices {
		inv.Devices = append(inv.Devices, serviceDevice{
			Type:             d.Type,
			Name:             d.Name,
			Model:            d.Model,
			IP:               d.IP,
			Firmware:         d.Firmware,
			Upgrade:          d.Upgrade,
			Networks:         d.Networks,
			FirmwareStatus:   d.FirmwareStatus,
			FirmwareAdvisory: d.FirmwareAdvisory,
		})
	}
	for _, sc := range specInv.ACLScopes {
		inv.ACLScopes = append(inv.ACLScopes, serviceACLScope{Scope: sc.Scope, RuleCount: sc.RuleCount})
	}
	return inv, nil
}
