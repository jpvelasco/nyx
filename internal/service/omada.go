package service

import (
	"context"
	"fmt"

	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
)

// OmadaOptions carries everything needed to talk to an Omada SDN controller.
// The client credentials are held only for the duration of a request; they
// are never written to logs, evidence, or tool output.
type OmadaOptions struct {
	Host          string
	ClientID      string
	ClientSecret  string
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
	DHCPStart   string `json:"dhcp_start,omitempty"`
	DHCPEnd     string `json:"dhcp_end,omitempty"`
	LeaseTime   int    `json:"lease_time,omitempty"`
	DHCPDNS     string `json:"dhcp_dns,omitempty"`
	IGMPSnoop   bool   `json:"igmp_snoop,omitempty"`
	MLDSnoop    bool   `json:"mld_snoop,omitempty"`
	DHCPL2Relay bool   `json:"dhcp_l2_relay,omitempty"`
	DHCPGuard   bool   `json:"dhcp_guard,omitempty"`
	DHCPv6Guard bool   `json:"dhcpv6_guard,omitempty"`
	Portal      bool   `json:"portal,omitempty"`
	AllLan      bool   `json:"all_lan,omitempty"`
	Primary     bool   `json:"primary,omitempty"`
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
// and any future CLI commands. NewClient is a seam for tests; PostAudit is the
// post-apply audit seam (service must not import the audit engine — callers
// inject it). A nil PostAudit reports "post-mutation audit unavailable".
type OmadaService struct {
	NewClient func(ctx context.Context, host string, skipTLSVerify bool, caCertPath string) (*omadabackend.Client, error)
	PostAudit func(ctx context.Context, spec *intent.Spec) (*models.AuditReport, error)
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
		out = append(out, flattenOmadaNetwork(n))
	}
	return out, nil
}

func flattenOmadaNetwork(n omadabackend.Network) OmadaNetwork {
	return OmadaNetwork{
		ID:          n.ID,
		Name:        n.Name,
		Purpose:     n.Purpose,
		VLANID:      n.VLANID,
		CIDR:        n.CIDR(),
		Gateway:     n.Gateway(),
		Isolated:    n.Isolated,
		DHCPEnabled: n.DHCPEnabled,
		DHCPStart:   n.DHCPStart,
		DHCPEnd:     n.DHCPEnd,
		LeaseTime:   n.LeaseTime,
		DHCPDNS:     n.DHCPDNS,
		IGMPSnoop:   n.IGMPSnoop,
		MLDSnoop:    n.MLDSnoop,
		DHCPL2Relay: n.DHCPL2Relay,
		DHCPGuard:   n.DHCPGuard,
		DHCPv6Guard: n.DHCPv6Guard,
		Portal:      n.Portal,
		AllLan:      n.AllLan,
		Primary:     n.Primary,
	}
}

// Import connects, imports the controller state, and produces an intent
// spec reflecting the observed design (networks, policies, assertions).
func (s *OmadaService) Import(ctx context.Context, opts OmadaOptions) (*OmadaImport, error) {
	result, err := omadabackend.ImportSpec(ctx, opts.Host, opts.ClientID, opts.ClientSecret, opts.Site,
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
	if err := client.Login(ctx, opts.ClientID, opts.ClientSecret); err != nil {
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

// withSession opens a logged-in site session, runs fn, then logs out.
func withSession[T any](s *OmadaService, ctx context.Context, opts OmadaOptions, fn func(*omadabackend.Client, string) (T, error)) (T, error) {
	var zero T
	client, site, err := s.session(ctx, opts)
	if err != nil {
		return zero, err
	}
	defer client.Logout(ctx) //nolint:errcheck
	return fn(client, site.EffectiveID())
}
