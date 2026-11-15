package service

import (
	"context"
	"fmt"

	providers "github.com/jpvelasco/nyx/internal/providers"
)

// OmadaPortForwarding is one NAT port-forwarding rule in a flat,
// agent-friendly shape (protocol as a name: ALL/TCP/UDP).
type OmadaPortForwarding struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Enabled          bool     `json:"enabled"`
	From             int      `json:"from"` // 0 = anywhere, 1 = limited addresses
	LimitedAddresses []string `json:"limited_addresses,omitempty"`
	ExternalPort     string   `json:"external_port"`
	ForwardIP        string   `json:"forward_ip"`
	ForwardPort      string   `json:"forward_port"`
	Protocol         string   `json:"protocol"`
	DMZ              bool     `json:"dmz"`
}

// OmadaOneToOneNAT is one one-to-one NAT rule.
type OmadaOneToOneNAT struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	InternalIP  string `json:"internal_ip"`
	ExternalIP  string `json:"external_ip"`
	DMZ         bool   `json:"dmz"`
	Description string `json:"description,omitempty"`
}

// OmadaALGSettings reports the enabled NAT application-layer gateways.
type OmadaALGSettings struct {
	FTP   bool `json:"ftp"`
	H323  bool `json:"h323"`
	PPTP  bool `json:"pptp"`
	SIP   bool `json:"sip"`
	IPsec bool `json:"ipsec"`
}

// OmadaFirewallSettings is the gateway firewall session-timeout and
// connection-configuration block. Timeouts are in seconds.
type OmadaFirewallSettings struct {
	ICMP           int `json:"icmp"`
	Other          int `json:"other"`
	TCPClose       int `json:"tcp_close"`
	TCPCloseWait   int `json:"tcp_close_wait"`
	TCPEstablished int `json:"tcp_established"`
	TCPFinWait     int `json:"tcp_fin_wait"`
	TCPLastAck     int `json:"tcp_last_ack"`
	TCPSynReceive  int `json:"tcp_syn_receive"`
	TCPSynSent     int `json:"tcp_syn_sent"`
	TCPTimeWait    int `json:"tcp_time_wait"`
	UDPOther       int `json:"udp_other"`
	UDPStream      int `json:"udp_stream"`

	BroadcastPing    bool `json:"broadcast_ping"`
	ReceiveRedirects bool `json:"receive_redirects"`
	SendRedirects    bool `json:"send_redirects"`
	SynCookies       bool `json:"syn_cookies"`
}

// OmadaNatFacts is the Omada-side NAT observation in one session: NAT rule
// counts, ALG and firewall settings, and whether a managed gateway is
// present. It is the input the topology report consumes for the Omada
// device.
type OmadaNatFacts struct {
	Site              string                `json:"site"`
	HasManagedGateway bool                  `json:"has_managed_gateway"`
	PortForwardRules  int                   `json:"port_forward_rules"`
	OneToOneRules     int                   `json:"one_to_one_rules"`
	ALG               OmadaALGSettings      `json:"alg"`
	Firewall          OmadaFirewallSettings `json:"firewall"`

	// gatewayIPs are the managed-gateway addresses used only to decide
	// path membership. They are never serialized or printed.
	gatewayIPs []string
}

// NatFacts gathers the Omada-side NAT observations in a single session.
// Every read must succeed: a partial picture would mislead the double-NAT
// verdict, so a failure is a hard error.
func (s *OmadaService) NatFacts(ctx context.Context, opts OmadaOptions) (*OmadaNatFacts, error) {
	client, site, err := s.session(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer client.Logout(ctx) //nolint:errcheck

	siteID := site.EffectiveID()
	devices, err := client.GetDevices(ctx, siteID)
	if err != nil {
		return nil, fmt.Errorf("fetching devices: %w", err)
	}
	pfs, err := client.GetPortForwardings(ctx, siteID)
	if err != nil {
		return nil, fmt.Errorf("fetching port forwardings: %w", err)
	}
	o2o, err := client.GetOneToOneNAT(ctx, siteID)
	if err != nil {
		return nil, fmt.Errorf("fetching one-to-one NAT rules: %w", err)
	}
	alg, err := client.GetALG(ctx, siteID)
	if err != nil {
		return nil, fmt.Errorf("fetching ALG settings: %w", err)
	}
	fw, err := client.GetFirewallSettings(ctx, siteID)
	if err != nil {
		return nil, fmt.Errorf("fetching firewall settings: %w", err)
	}
	facts := &OmadaNatFacts{
		Site:             site.Name,
		PortForwardRules: len(pfs),
		OneToOneRules:    len(o2o),
		ALG: OmadaALGSettings{
			FTP: alg.FTP, H323: alg.H323, PPTP: alg.PPTP, SIP: alg.SIP, IPsec: alg.IPsec,
		},
		Firewall: OmadaFirewallSettings{
			ICMP: fw.ICMP, Other: fw.Other, TCPClose: fw.TCPClose, TCPCloseWait: fw.TCPCloseWait,
			TCPEstablished: fw.TCPEstablished, TCPFinWait: fw.TCPFinWait, TCPLastAck: fw.TCPLastAck,
			TCPSynReceive: fw.TCPSynReceive, TCPSynSent: fw.TCPSynSent, TCPTimeWait: fw.TCPTimeWait,
			UDPOther: fw.UDPOther, UDPStream: fw.UDPStream,
			BroadcastPing: fw.BroadcastPing, ReceiveRedirects: fw.ReceiveRedirects,
			SendRedirects: fw.SendRedirects, SynCookies: fw.SynCookies,
		},
	}
	for _, d := range devices {
		if d.IsGateway() {
			facts.HasManagedGateway = true
			if d.IP != "" {
				facts.gatewayIPs = append(facts.gatewayIPs, d.IP)
			}
		}
	}
	return facts, nil
}

// ListPortForwardings returns the site's NAT port-forwarding rules.
func (s *OmadaService) ListPortForwardings(ctx context.Context, opts OmadaOptions) ([]OmadaPortForwarding, error) {
	client, site, err := s.session(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer client.Logout(ctx) //nolint:errcheck

	rows, err := client.GetPortForwardings(ctx, site.EffectiveID())
	if err != nil {
		return nil, fmt.Errorf("fetching port forwardings: %w", err)
	}
	out := make([]OmadaPortForwarding, 0, len(rows))
	for _, r := range rows {
		out = append(out, OmadaPortForwarding{
			ID:               r.ID,
			Name:             r.Name,
			Enabled:          r.Enabled,
			From:             r.From,
			LimitedAddresses: r.LimitedAddresses,
			ExternalPort:     r.ExternalPort,
			ForwardIP:        r.ForwardIP,
			ForwardPort:      r.ForwardPort,
			Protocol:         r.Protocol,
			DMZ:              r.DMZ,
		})
	}
	return out, nil
}

// ListOneToOneNAT returns the site's one-to-one NAT rules.
func (s *OmadaService) ListOneToOneNAT(ctx context.Context, opts OmadaOptions) ([]OmadaOneToOneNAT, error) {
	client, site, err := s.session(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer client.Logout(ctx) //nolint:errcheck

	rules, err := client.GetOneToOneNAT(ctx, site.EffectiveID())
	if err != nil {
		return nil, fmt.Errorf("fetching one-to-one NAT rules: %w", err)
	}
	out := make([]OmadaOneToOneNAT, 0, len(rules))
	for _, r := range rules {
		out = append(out, OmadaOneToOneNAT{
			ID:          r.ID,
			Name:        r.Name,
			Enabled:     r.Enabled,
			InternalIP:  r.InternalIP,
			ExternalIP:  r.ExternalIP,
			DMZ:         r.DMZ,
			Description: r.Description,
		})
	}
	return out, nil
}

// GetALGSettings returns the site's NAT application-layer gateway settings.
func (s *OmadaService) GetALGSettings(ctx context.Context, opts OmadaOptions) (*OmadaALGSettings, error) {
	client, site, err := s.session(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer client.Logout(ctx) //nolint:errcheck

	alg, err := client.GetALG(ctx, site.EffectiveID())
	if err != nil {
		return nil, fmt.Errorf("fetching ALG settings: %w", err)
	}
	return &OmadaALGSettings{FTP: alg.FTP, H323: alg.H323, PPTP: alg.PPTP, SIP: alg.SIP, IPsec: alg.IPsec}, nil
}

// GetFirewallSettings returns the site's gateway firewall settings.
func (s *OmadaService) GetFirewallSettings(ctx context.Context, opts OmadaOptions) (*OmadaFirewallSettings, error) {
	client, site, err := s.session(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer client.Logout(ctx) //nolint:errcheck

	fw, err := client.GetFirewallSettings(ctx, site.EffectiveID())
	if err != nil {
		return nil, fmt.Errorf("fetching firewall settings: %w", err)
	}
	return &OmadaFirewallSettings{
		ICMP:             fw.ICMP,
		Other:            fw.Other,
		TCPClose:         fw.TCPClose,
		TCPCloseWait:     fw.TCPCloseWait,
		TCPEstablished:   fw.TCPEstablished,
		TCPFinWait:       fw.TCPFinWait,
		TCPLastAck:       fw.TCPLastAck,
		TCPSynReceive:    fw.TCPSynReceive,
		TCPSynSent:       fw.TCPSynSent,
		TCPTimeWait:      fw.TCPTimeWait,
		UDPOther:         fw.UDPOther,
		UDPStream:        fw.UDPStream,
		BroadcastPing:    fw.BroadcastPing,
		ReceiveRedirects: fw.ReceiveRedirects,
		SendRedirects:    fw.SendRedirects,
		SynCookies:       fw.SynCookies,
	}, nil
}

// OmadaNatApplyRequest is an Omada NAT plan/apply request (#139). The
// surface mirrors the OPNsense pair so agents can carry the same intent
// across providers; the Omada Open API exposes no live-site NAT write
// path, so PlanNat/ApplyNat HOLD clearly with evidence.
type OmadaNatApplyRequest struct {
	Operation string // "port_forward" | "one_to_one" (Omada has no source_nat)
	Action    string // "create" | "update" | "delete" | "toggle" (default "create")
	RuleUUID  string // required for update/delete/toggle
	Spec      providers.NatRuleSpec
	DryRun    bool
}

// omadaNatMutation resolves the Omada provider's NAT mutation surface.
func (s *OmadaService) omadaNatMutation() (providers.NatMutationProvider, error) {
	p := providers.Get("omada")
	if p == nil {
		return nil, fmt.Errorf("provider omada not registered")
	}
	mutator, ok := p.(providers.NatMutationProvider)
	if !ok {
		return nil, fmt.Errorf("provider omada does not implement NAT mutation")
	}
	return mutator, nil
}

func omadaNatProvOpts(opts OmadaOptions) providers.ImportOptions {
	return providers.ImportOptions{
		Host:          opts.Host,
		ClientID:      opts.ClientID,
		ClientSecret:  opts.ClientSecret,
		Site:          opts.Site,
		SkipTLSVerify: opts.SkipTLSVerify,
		CACertPath:    opts.CACertPath,
	}
}

// PlanNat previews an Omada NAT mutation: the Open API exposes no
// live-site NAT write path, so the plan refuses with the current rules
// as Before evidence and the write-surface explanation.
func (s *OmadaService) PlanNat(ctx context.Context, opts OmadaOptions, req OmadaNatApplyRequest) (*providers.NatPlan, error) {
	mutator, err := s.omadaNatMutation()
	if err != nil {
		return nil, err
	}
	return mutator.PlanNat(ctx, providers.NatApplyRequest{
		Operation: req.Operation,
		Action:    req.Action,
		RuleUUID:  req.RuleUUID,
		Spec:      req.Spec,
		DryRun:    req.DryRun,
	}, omadaNatProvOpts(opts))
}

// ApplyNat refuses every Omada NAT mutation with identical Before/After
// evidence — nothing can mutate, dry-run or not.
func (s *OmadaService) ApplyNat(ctx context.Context, opts OmadaOptions, req OmadaNatApplyRequest) (*providers.NatApplyResult, error) {
	mutator, err := s.omadaNatMutation()
	if err != nil {
		return nil, err
	}
	return mutator.ApplyNat(ctx, providers.NatApplyRequest{
		Operation: req.Operation,
		Action:    req.Action,
		RuleUUID:  req.RuleUUID,
		Spec:      req.Spec,
		DryRun:    req.DryRun,
	}, omadaNatProvOpts(opts))
}
