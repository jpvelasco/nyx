package service

import (
	"context"
	"fmt"

	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
	"github.com/jpvelasco/nyx/internal/intent"
)

// OmadaOptions carries everything needed to talk to an Omada SDN controller.
// The password is held only for the duration of a request; it is never
// written to logs, evidence, or tool output.
type OmadaOptions struct {
	Host          string
	Username      string
	Password      string
	Site          string
	SkipTLSVerify bool
	CACertPath    string
}

// OmadaInfo is the unauthenticated controller metadata surfaced to agents.
type OmadaInfo struct {
	Provider   string `json:"provider"`
	Host       string `json:"host"`
	Version    string `json:"version"`
	APIVersion string `json:"api_version"`
	OmadaCID   string `json:"omada_cid"`
	Configured bool   `json:"configured"`
}

// OmadaNetwork is a LAN network/VLAN with derived CIDR and gateway.
type OmadaNetwork struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Purpose     string `json:"purpose"`
	VLANID      int    `json:"vlan_id"`
	CIDR        string `json:"cidr"`
	Gateway     string `json:"gateway"`
	Isolated    bool   `json:"isolated"`
	DHCPEnabled bool   `json:"dhcp_enabled"`
}

// OmadaACLRule is a switch or gateway ACL rule in a flat, agent-friendly shape.
type OmadaACLRule struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Enabled    bool   `json:"enabled"`
	Policy     string `json:"policy"`
	Protocols  string `json:"protocols"`
	SourceType string `json:"source_type"`
	SourceName string `json:"source_name"`
	DestType   string `json:"dest_type"`
	DestName   string `json:"dest_name"`
	Index      int    `json:"index"`
}

// OmadaClient is a connected client in a flat, agent-friendly shape.
type OmadaClient struct {
	MAC         string `json:"mac"`
	IP          string `json:"ip"`
	Name        string `json:"name"`
	Hostname    string `json:"hostname"`
	NetworkName string `json:"network_name"`
	SSID        string `json:"ssid"`
	VLANID      int    `json:"vlan_id"`
	Wireless    bool   `json:"wireless"`
	Vendor      string `json:"vendor"`
	DeviceType  string `json:"device_type"`
	Active      bool   `json:"active"`
	Uptime      int64  `json:"uptime_seconds"`
}

// OmadaImport is the generated intent spec plus the fetch summary, letting
// agents compare intended state (spec) against observed state.
type OmadaImport struct {
	Spec              *intent.Spec `json:"spec"`
	Site              string       `json:"site"`
	ControllerVersion string       `json:"controller_version"`
	NetworkCount      int          `json:"network_count"`
	ACLRuleCount      int          `json:"acl_rule_count"`
	ClientCount       int          `json:"client_count"`
	Warnings          []string     `json:"warnings"`
}

// OmadaService exposes the Omada observation surface shared by the MCP server
// and any future CLI commands. NewClient is a seam for tests.
type OmadaService struct {
	NewClient func(ctx context.Context, host string, skipTLSVerify bool, caCertPath string) (*omadabackend.Client, error)
}

// NewOmadaService creates an OmadaService using the real controller client.
func NewOmadaService() *OmadaService {
	return &OmadaService{NewClient: omadabackend.NewClient}
}

// Info fetches controller metadata without authentication.
func (s *OmadaService) Info(ctx context.Context, opts OmadaOptions) (*OmadaInfo, error) {
	client, err := s.newClient(ctx, opts)
	if err != nil {
		return nil, err
	}
	info := client.Info()
	return &OmadaInfo{
		Provider:   "omada",
		Host:       opts.Host,
		Version:    info.ControllerVer,
		APIVersion: info.APIVer,
		OmadaCID:   info.OmadaCID,
		Configured: info.Configured,
	}, nil
}

// ListNetworks returns the LAN networks of the selected site.
func (s *OmadaService) ListNetworks(ctx context.Context, opts OmadaOptions) ([]OmadaNetwork, error) {
	client, site, err := s.session(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer client.Logout(ctx) //nolint:errcheck

	nets, err := client.GetNetworks(ctx, site.EffectiveID())
	if err != nil {
		return nil, fmt.Errorf("fetching networks: %w", err)
	}
	out := make([]OmadaNetwork, 0, len(nets))
	for _, n := range nets {
		out = append(out, OmadaNetwork{
			ID:          n.ID,
			Name:        n.Name,
			Purpose:     n.Purpose,
			VLANID:      n.VLANID,
			CIDR:        n.CIDR(),
			Gateway:     n.Gateway(),
			Isolated:    n.Isolated,
			DHCPEnabled: n.DHCPEnabled,
		})
	}
	return out, nil
}

// ListACLs returns switch and gateway ACL rules for the selected site,
// switch rules first. Both fetches must succeed so agents never see a
// partial rule set.
func (s *OmadaService) ListACLs(ctx context.Context, opts OmadaOptions) ([]OmadaACLRule, error) {
	client, site, err := s.session(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer client.Logout(ctx) //nolint:errcheck

	rules, err := client.GetACLRules(ctx, site.EffectiveID())
	if err != nil {
		return nil, fmt.Errorf("fetching ACL rules: %w", err)
	}
	gwRules, err := client.GetGatewayACLRules(ctx, site.EffectiveID())
	if err != nil {
		return nil, fmt.Errorf("fetching gateway ACL rules: %w", err)
	}

	out := make([]OmadaACLRule, 0, len(rules)+len(gwRules))
	for _, r := range append(rules, gwRules...) {
		out = append(out, OmadaACLRule{
			ID:         r.ID,
			Name:       r.Name,
			Enabled:    r.Status,
			Policy:     r.Policy,
			Protocols:  r.Protocols,
			SourceType: r.SourceType,
			SourceName: r.SourceName,
			DestType:   r.DestType,
			DestName:   r.DestName,
			Index:      r.Index,
		})
	}
	return out, nil
}

// ListClients returns the connected clients of the selected site.
func (s *OmadaService) ListClients(ctx context.Context, opts OmadaOptions) ([]OmadaClient, error) {
	client, site, err := s.session(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer client.Logout(ctx) //nolint:errcheck

	clients, err := client.GetClients(ctx, site.EffectiveID())
	if err != nil {
		return nil, fmt.Errorf("fetching clients: %w", err)
	}
	out := make([]OmadaClient, 0, len(clients))
	for _, c := range clients {
		out = append(out, OmadaClient{
			MAC:         c.MAC,
			IP:          c.IP,
			Name:        c.Name,
			Hostname:    c.Hostname,
			NetworkName: c.NetworkName,
			SSID:        c.SSID,
			VLANID:      c.VLANID,
			Wireless:    c.Wireless,
			Vendor:      c.Vendor,
			DeviceType:  c.DeviceType,
			Active:      c.Active,
			Uptime:      c.Uptime,
		})
	}
	return out, nil
}

// Import connects, imports the controller state, and produces an intent
// spec reflecting the observed design (networks, policies, assertions).
func (s *OmadaService) Import(ctx context.Context, opts OmadaOptions) (*OmadaImport, error) {
	result, err := omadabackend.ImportSpec(ctx, opts.Host, opts.Username, opts.Password, opts.Site,
		false, opts.SkipTLSVerify, opts.CACertPath, nil)
	if err != nil {
		return nil, err
	}
	return &OmadaImport{
		Spec:              result.Spec,
		Site:              result.Site.Name,
		ControllerVersion: result.ControllerVersion,
		NetworkCount:      result.NetworkCount,
		ACLRuleCount:      result.ACLRuleCount,
		ClientCount:       result.ClientCount,
		Warnings:          result.Warnings,
	}, nil
}

func (s *OmadaService) newClient(ctx context.Context, opts OmadaOptions) (*omadabackend.Client, error) {
	return s.NewClient(ctx, opts.Host, opts.SkipTLSVerify, opts.CACertPath)
}

// session connects, authenticates, and resolves the target site. The caller
// owns the returned client and must Logout when done.
func (s *OmadaService) session(ctx context.Context, opts OmadaOptions) (*omadabackend.Client, omadabackend.Site, error) {
	client, err := s.newClient(ctx, opts)
	if err != nil {
		return nil, omadabackend.Site{}, err
	}
	if err := client.Login(ctx, opts.Username, opts.Password); err != nil {
		return nil, omadabackend.Site{}, err
	}
	sites, err := client.GetSites(ctx)
	if err != nil {
		_ = client.Logout(ctx)
		return nil, omadabackend.Site{}, fmt.Errorf("fetching sites: %w", err)
	}
	site, err := omadabackend.SelectSite(sites, opts.Site)
	if err != nil {
		_ = client.Logout(ctx)
		return nil, omadabackend.Site{}, err
	}
	return client, site, nil
}
