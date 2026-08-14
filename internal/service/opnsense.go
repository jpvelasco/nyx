package service

import (
	"context"

	opnsensebackend "github.com/jpvelasco/nyx/internal/providers/opnsense"
)

// OpnsenseOptions carries everything needed to talk to an OPNsense firewall
// via its REST API. The API secret is held only for the duration of a
// request; it is never written to logs, evidence, or tool output.
type OpnsenseOptions struct {
	Host          string
	APIKey        string
	APISecret     string
	SkipTLSVerify bool
	CACertPath    string
}

// OpnsenseInfo is the firmware metadata surfaced to agents.
type OpnsenseInfo struct {
	Provider string `json:"provider"`
	Host     string `json:"host"`
	Version  string `json:"version"`
	Product  string `json:"product"`
	Arch     string `json:"arch"`
}

// OpnsenseInterface is a firewall interface with its IP configuration.
type OpnsenseInterface struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	DHCP        bool   `json:"dhcp"`
	IP          string `json:"ip"`
	Subnet      int    `json:"subnet"`
	Gateway     string `json:"gateway"`
}

// OpnsenseFirewallRule is a firewall filter rule in a flat, agent-friendly
// shape. Disabled is true when the rule is not active.
type OpnsenseFirewallRule struct {
	UUID        string   `json:"uuid"`
	Enabled     bool     `json:"enabled"`
	Disabled    bool     `json:"disabled"`
	Action      string   `json:"action"`
	Interfaces  []string `json:"interfaces"`
	Protocol    string   `json:"protocol"`
	Source      string   `json:"source"`
	Destination string   `json:"destination"`
	Label       string   `json:"label"`
}

// OpnsenseClient is a DHCP lease — OPNsense does not expose live client
// state, so leases are the best host inventory available.
type OpnsenseClient struct {
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

// OpnsenseService exposes the OPNsense observation surface shared by the MCP
// server and any future CLI commands. NewClient is a seam for tests.
type OpnsenseService struct {
	NewClient func(host, apiKey, apiSecret string, skipTLSVerify bool, caCertPath string) *opnsensebackend.Client
}

// NewOpnsenseService creates an OpnsenseService using the real client.
func NewOpnsenseService() *OpnsenseService {
	return &OpnsenseService{NewClient: opnsensebackend.NewClient}
}

// Info fetches firmware metadata from the firewall.
func (s *OpnsenseService) Info(ctx context.Context, opts OpnsenseOptions) (*OpnsenseInfo, error) {
	client := s.client(opts)
	fw, err := client.GetFirmwareInfo(ctx)
	if err != nil {
		return nil, err
	}
	return &OpnsenseInfo{
		Provider: "opnsense",
		Host:     opts.Host,
		Version:  fw.ProductVersion,
		Product:  fw.ProductName,
		Arch:     fw.ProductArch,
	}, nil
}

// ListInterfaces returns the firewall interfaces with IP configuration.
func (s *OpnsenseService) ListInterfaces(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseInterface, error) {
	client := s.client(opts)
	ifaces, err := client.GetInterfaces(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]OpnsenseInterface, 0, len(ifaces))
	for _, i := range ifaces {
		out = append(out, OpnsenseInterface{
			Name:        i.Name,
			Description: i.Description,
			DHCP:        i.DHCP,
			IP:          i.IP,
			Subnet:      i.Subnet,
			Gateway:     i.Gateway,
		})
	}
	return out, nil
}

// ListFirewallRules returns the firewall filter rules.
func (s *OpnsenseService) ListFirewallRules(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseFirewallRule, error) {
	client := s.client(opts)
	rules, err := client.GetFirewallRules(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]OpnsenseFirewallRule, 0, len(rules))
	for _, r := range rules {
		out = append(out, OpnsenseFirewallRule{
			UUID:        r.RuleUUID,
			Enabled:     !r.Disabled,
			Disabled:    r.Disabled,
			Action:      r.Action,
			Interfaces:  r.Interface,
			Protocol:    r.Protocol,
			Source:      r.Source,
			Destination: r.Destination,
			Label:       r.Label,
		})
	}
	return out, nil
}

// ListClients returns the DHCP leases as the host inventory.
func (s *OpnsenseService) ListClients(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseClient, error) {
	client := s.client(opts)
	leases, err := client.GetDHCPLeases(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]OpnsenseClient, 0, len(leases))
	for _, l := range leases {
		out = append(out, OpnsenseClient{MAC: l.MAC, IP: l.IP, Hostname: l.Hostname})
	}
	return out, nil
}

func (s *OpnsenseService) client(opts OpnsenseOptions) *opnsensebackend.Client {
	return s.NewClient(opts.Host, opts.APIKey, opts.APISecret, opts.SkipTLSVerify, opts.CACertPath)
}
