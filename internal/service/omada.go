package service

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	providers "github.com/jpvelasco/nyx/internal/providers"
	omadaprovider "github.com/jpvelasco/nyx/internal/providers/omada"
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

// OmadaPolicyDiff describes one policy pair in a plan: unchanged, to add, to
// remove, or to change. Action is the effective action; CurrentAction and
// ProposedAction are set on changes so the agent sees both sides.
type OmadaPolicyDiff struct {
	Name           string `json:"name,omitempty"`
	From           string `json:"from"`
	To             string `json:"to"`
	Action         string `json:"action,omitempty"`
	CurrentAction  string `json:"current_action,omitempty"`
	ProposedAction string `json:"proposed_action,omitempty"`
}

// OmadaPlan is a read-only actuator preview: the difference between the
// controller's current ACL rules and a proposed intent spec. No changes are
// applied. Warnings flag proposal endpoints that are not declared networks.
type OmadaPlan struct {
	Site          string            `json:"site"`
	ProposedSite  string            `json:"proposed_site"`
	CurrentRules  int               `json:"current_rules"`
	ProposedRules int               `json:"proposed_rules"`
	Unchanged     []OmadaPolicyDiff `json:"unchanged"`
	ToAdd         []OmadaPolicyDiff `json:"to_add"`
	ToRemove      []OmadaPolicyDiff `json:"to_remove"`
	ToChange      []OmadaPolicyDiff `json:"to_change"`
	Warnings      []string          `json:"warnings"`
}

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

// OmadaUplinkInfo is one device uplink observation: which managed device
// (and port) the queried MAC is cabled into.
type OmadaUplinkInfo struct {
	MAC              string `json:"mac"`
	UplinkDeviceMAC  string `json:"uplink_device_mac,omitempty"`
	UplinkDeviceName string `json:"uplink_device_name,omitempty"`
	UplinkDevicePort string `json:"uplink_device_port,omitempty"`
	LinkSpeed        int    `json:"link_speed"`
	Duplex           int    `json:"duplex"`
}

// OmadaSwitchPort is one switch port row with its VLAN membership resolved:
// the overview row plus the LAN profile it references. A port's VLAN
// membership is its native (untagged) network plus its tagged set; the
// Tagged list holds resolved network names (order-insensitive for matching).
type OmadaSwitchPort struct {
	Port               int      `json:"port"`
	PortName           string   `json:"port_name,omitempty"`
	SwitchMAC          string   `json:"switch_mac"`
	SwitchName         string   `json:"switch_name,omitempty"`
	ConnectedStatus    int      `json:"connected_status"`
	Disabled           bool     `json:"disabled,omitempty"`
	NetworkMode        int      `json:"network_mode"` // 0 Trunk, 1 Access
	NativeNetwork      string   `json:"native_network,omitempty"`
	NativeBridgeVLAN   int      `json:"native_bridge_vlan,omitempty"`
	NetworkTagsSetting int      `json:"network_tags_setting"` // 0 Allow All, 1 Block All, 2 Custom
	ProfileID          string   `json:"profile_id,omitempty"`
	ProfileName        string   `json:"profile_name,omitempty"`
	ProfileOverride    bool     `json:"profile_override,omitempty"`
	Tagged             []string `json:"tagged"`
}

// OmadaLanProfile is a site-wide LAN profile with resolved network names:
// the native (untagged) network plus the tagged set.
type OmadaLanProfile struct {
	ID                   string   `json:"id,omitempty"`
	Flag                 int      `json:"flag,omitempty"` // 0 default, 1 native, 2 custom
	Name                 string   `json:"name"`
	NativeNetwork        string   `json:"native_network,omitempty"`
	TaggedNetworks       []string `json:"tagged_networks"`
	Dot1x                int      `json:"dot1x"`
	PortIsolationEnable  bool     `json:"port_isolation_enable"`
	SpanningTreeEnable   bool     `json:"spanning_tree_enable"`
	LoopbackDetectEnable bool     `json:"loopback_detect_enable"`
}

// OmadaPortPlan is a read-only preview of bringing one port to the desired
// VLAN membership: what the port currently has, the desired membership,
// and whether an existing LAN profile can be reused or a new one must be
// created. Nothing is applied.
type OmadaPortPlan struct {
	Site           string                  `json:"site"`
	SwitchMAC      string                  `json:"switch_mac"`
	Port           int                     `json:"port"`
	Current        *OmadaSwitchPort        `json:"current,omitempty"`
	CurrentProfile *OmadaLanProfile        `json:"current_profile,omitempty"`
	Desired        OmadaPortProfileRequest `json:"desired"`
	Outcome        string                  `json:"outcome"` // "unchanged" | "rebind" | "create"
	ProfileID      string                  `json:"profile_id,omitempty"`
	ProfileName    string                  `json:"profile_name,omitempty"`
	ProfileCreate  bool                    `json:"profile_create,omitempty"`
	Warnings       []string                `json:"warnings,omitempty"`
}

// OmadaPortProfileRequest describes the desired VLAN membership of one
// port: the native (untagged) network plus the tagged network set. The
// native network is the port's single untagged VLAN, so the desired
// untagged set is derived from it. Names are LAN network names; the native
// network must not also appear in the tagged list (controller rule).
type OmadaPortProfileRequest struct {
	SwitchMAC   string   `json:"switch_mac"`
	Port        int      `json:"port"`
	Native      string   `json:"native"` // network name (required)
	Tagged      []string `json:"tagged,omitempty"`
	ProfileName string   `json:"profile_name,omitempty"` // optional; derived when empty
}

// OmadaPortProfileApplyResult is the structured outcome of a port-profile
// apply with before/after evidence (the port row joined to its referenced
// LAN profile).
type OmadaPortProfileApplyResult struct {
	DryRun        bool     `json:"dry_run"`
	Outcome       string   `json:"outcome"` // "unchanged" | "bound" | "created_and_bound" (a dry run previews the real-apply outcome)
	SwitchMAC     string   `json:"switch_mac"`
	Port          int      `json:"port"`
	ProfileID     string   `json:"profile_id,omitempty"`
	ProfileName   string   `json:"profile_name,omitempty"`
	ProfileCreate bool     `json:"profile_create,omitempty"`
	Before        string   `json:"before"`
	After         string   `json:"after"`
	Warnings      []string `json:"warnings,omitempty"`
}

// GetUplinkInfo returns the uplink device (and port) for each queried MAC.
// MACs with no observed uplink are simply absent from the result.
func (s *OmadaService) GetUplinkInfo(ctx context.Context, opts OmadaOptions, macs []string) ([]OmadaUplinkInfo, error) {
	client, site, err := s.session(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer client.Logout(ctx) //nolint:errcheck

	rows, err := client.GetUplinkInfo(ctx, site.EffectiveID(), macs)
	if err != nil {
		return nil, err
	}
	out := make([]OmadaUplinkInfo, 0, len(rows))
	for _, r := range rows {
		out = append(out, OmadaUplinkInfo{
			MAC:              r.MAC,
			UplinkDeviceMAC:  r.UplinkDeviceMAC,
			UplinkDeviceName: r.UplinkDeviceName,
			UplinkDevicePort: r.UplinkDevicePort,
			LinkSpeed:        r.LinkSpeed,
			Duplex:           r.Duplex,
		})
	}
	return out, nil
}

// ListSwitchPorts returns the site's switch port rows with each port's VLAN
// membership resolved from the LAN profile it references. switchMAC filters
// to one switch when non-empty.
func (s *OmadaService) ListSwitchPorts(ctx context.Context, opts OmadaOptions, switchMAC string) ([]OmadaSwitchPort, error) {
	client, site, err := s.session(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer client.Logout(ctx) //nolint:errcheck

	siteID := site.EffectiveID()
	ports, profiles, nets, err := fetchPortMembership(ctx, client, siteID)
	if err != nil {
		return nil, err
	}
	netName := networkNameByID(nets)
	wantMac := omadabackend.NormalizeMAC(switchMAC)
	out := make([]OmadaSwitchPort, 0, len(ports))
	for i := range ports {
		if switchMAC != "" && omadabackend.NormalizeMAC(ports[i].SwitchMAC) != wantMac {
			continue
		}
		out = append(out, *portObservation(ports[i], profiles, netName))
	}
	return out, nil
}

// ListLanProfiles returns the site's LAN profiles with resolved network
// names.
func (s *OmadaService) ListLanProfiles(ctx context.Context, opts OmadaOptions) ([]OmadaLanProfile, error) {
	client, site, err := s.session(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer client.Logout(ctx) //nolint:errcheck

	siteID := site.EffectiveID()
	profiles, err := client.GetLanProfiles(ctx, siteID)
	if err != nil {
		return nil, err
	}
	nets, err := client.GetNetworks(ctx, siteID)
	if err != nil {
		return nil, err
	}
	netName := networkNameByID(nets)
	out := make([]OmadaLanProfile, 0, len(profiles))
	for i := range profiles {
		out = append(out, *serviceLanProfile(profiles[i], netName))
	}
	return out, nil
}

// PlanPort previews bringing one port to the desired VLAN membership
// (native network plus tagged set). It is read-only: the only writes a dry
// run would perform are stated in the result (create the LAN profile if no
// member-matching profile exists, then bind it to the port).
func (s *OmadaService) PlanPort(ctx context.Context, opts OmadaOptions, req OmadaPortProfileRequest) (*OmadaPortPlan, error) {
	client, site, err := s.session(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer client.Logout(ctx) //nolint:errcheck

	ports, profiles, nets, err := fetchPortMembership(ctx, client, site.EffectiveID())
	if err != nil {
		return nil, err
	}
	plan, _, _, err := planPortFromState(req, ports, profiles, nets)
	if err != nil {
		return nil, err
	}
	plan.Site = site.Name
	return plan, nil
}

// ApplyPortProfile brings one port to the desired VLAN membership (native
// plus tagged): find an existing LAN profile whose (native, tagged,
// untagged=native) membership matches, create one when none does, then bind
// it to the port. DryRun previews without mutating. Before/after evidence is
// the port row joined to its referenced profile.
func (s *OmadaService) ApplyPortProfile(ctx context.Context, opts OmadaOptions, req OmadaPortProfileRequest, dryRun bool) (*OmadaPortProfileApplyResult, error) {
	client, site, err := s.session(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer client.Logout(ctx) //nolint:errcheck

	siteID := site.EffectiveID()
	ports, profiles, nets, err := fetchPortMembership(ctx, client, siteID)
	if err != nil {
		return nil, err
	}
	plan, prof, create, err := planPortFromState(req, ports, profiles, nets)
	if err != nil {
		return nil, err
	}
	// The plan read the still-unmutated state, so its port row is the
	// before evidence — no second fetch round trip.
	before, err := portEvidenceJSON(ports, profiles, nets, req.SwitchMAC, req.Port)
	if err != nil {
		return nil, err
	}
	res := &OmadaPortProfileApplyResult{
		DryRun:        dryRun,
		Outcome:       plan.Outcome,
		SwitchMAC:     plan.SwitchMAC,
		Port:          plan.Port,
		ProfileID:     plan.ProfileID,
		ProfileName:   plan.ProfileName,
		ProfileCreate: plan.ProfileCreate,
		Before:        before,
		After:         before,
		Warnings:      plan.Warnings,
	}
	if dryRun {
		// No write, no re-read. Report the outcome a real apply would
		// produce (unchanged stays unchanged).
		switch plan.Outcome {
		case "create":
			res.Outcome = "created_and_bound"
		case "rebind":
			res.Outcome = "bound"
		}
		return res, nil
	}
	if plan.Outcome == "unchanged" {
		// The port already has the desired membership — no write, no
		// re-read; the after evidence is the before read.
		return res, nil
	}

	if create {
		id, cerr := client.CreateLanProfile(ctx, siteID, *prof)
		if cerr != nil {
			return nil, cerr
		}
		prof.ID = id
	}
	res.ProfileID = prof.ID // the plan's id is empty until the create runs
	if err := client.SetPortProfile(ctx, siteID, req.SwitchMAC, req.Port, prof.ID); err != nil {
		if create {
			// The controller now has a new LAN profile the retry will
			// reuse — name it so the failure is reconcilable.
			return nil, fmt.Errorf("LAN profile %q (id %s) was created but binding it failed: %w", prof.Name, prof.ID, err)
		}
		return nil, err
	}
	if plan.Outcome == "create" {
		res.Outcome = "created_and_bound"
	} else {
		res.Outcome = "bound"
	}
	afterPorts, afterProfiles, afterNets, err := fetchPortMembership(ctx, client, siteID)
	if err != nil {
		return nil, fmt.Errorf("re-reading port state after apply: %w", err)
	}
	res.After, err = portEvidenceJSON(afterPorts, afterProfiles, afterNets, req.SwitchMAC, req.Port)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// fetchPortMembership pulls the three collections every port-mapping read
// needs (port rows, LAN profiles, networks) in one go. All three must
// succeed: a partial picture would mislabel a port's VLAN membership.
func fetchPortMembership(ctx context.Context, client *omadabackend.Client, siteID string) ([]omadabackend.SwitchPort, []omadabackend.LanProfile, []omadabackend.Network, error) {
	ports, err := client.GetSwitchPortsOverview(ctx, siteID)
	if err != nil {
		return nil, nil, nil, err
	}
	profiles, err := client.GetLanProfiles(ctx, siteID)
	if err != nil {
		return nil, nil, nil, err
	}
	nets, err := client.GetNetworks(ctx, siteID)
	if err != nil {
		return nil, nil, nil, err
	}
	return ports, profiles, nets, nil
}

// planPortFromState resolves the desired membership against an already-
// fetched port overview, LAN profiles, and site networks and decides the
// outcome. It returns the plan, the profile to bind (a fresh one when a
// create is needed), and whether a create is required.
func planPortFromState(req OmadaPortProfileRequest, ports []omadabackend.SwitchPort, profiles []omadabackend.LanProfile, nets []omadabackend.Network) (*OmadaPortPlan, *omadabackend.LanProfile, bool, error) {
	var cur *omadabackend.SwitchPort
	wantMAC := omadabackend.NormalizeMAC(req.SwitchMAC)
	for i := range ports {
		if ports[i].Port == req.Port && omadabackend.NormalizeMAC(ports[i].SwitchMAC) == wantMAC {
			cur = &ports[i]
			break
		}
	}
	if cur == nil {
		return nil, nil, false, fmt.Errorf("port %d not found on switch %s — check the switch MAC (compare `nyx omada switch-ports`)", req.Port, req.SwitchMAC)
	}

	nativeID, err := resolveNetworkID(nets, req.Native)
	if err != nil {
		return nil, nil, false, err
	}
	tagIDs, err := resolveNetworkIDList(nets, req.Tagged)
	if err != nil {
		return nil, nil, false, err
	}
	untagIDs := []string{nativeID} // the native network is the port's single untagged VLAN
	if idInList(tagIDs, nativeID) {
		return nil, nil, false, fmt.Errorf("native network %q must not also appear in the tagged list (controller rule)", req.Native)
	}

	netName := networkNameByID(nets)
	plan := &OmadaPortPlan{
		SwitchMAC: req.SwitchMAC,
		Port:      req.Port,
		Desired:   req,
	}
	plan.Current = portObservation(*cur, profiles, netName)
	if p := findProfileByID(profiles, cur.ProfileID); p != nil {
		plan.CurrentProfile = serviceLanProfile(*p, netName)
	}
	if cur.ProfileOverride {
		// The effective membership can differ from the bound profile, so
		// every outcome decision below is advisory until the port is
		// re-verified after the (non-)write.
		plan.Warnings = append(plan.Warnings,
			"port has a profile override enabled: its effective VLAN membership may differ from the bound profile")
	}
	// Idempotent first: if the port's currently-bound profile already has
	// the desired membership, nothing needs to happen.
	if bound := findProfileByID(profiles, cur.ProfileID); bound != nil &&
		omadabackend.ProfileMatchesMembership(*bound, nativeID, tagIDs, untagIDs) {
		plan.Outcome = "unchanged"
		plan.ProfileID = bound.ID
		plan.ProfileName = bound.Name
		return plan, bound, false, nil
	}
	// Otherwise reuse the first profile whose membership matches (rebind),
	// or create one when none does.
	if member := omadabackend.FindLanProfile(profiles, nativeID, tagIDs, untagIDs); member != nil {
		plan.Outcome = "rebind"
		plan.ProfileID = member.ID
		plan.ProfileName = member.Name
		return plan, member, false, nil
	}
	plan.Outcome = "create"

	name := req.ProfileName
	if name == "" {
		name = derivePortProfileName(req)
	}
	profile := &omadabackend.LanProfile{
		Name:              name,
		PoE:               omadabackend.PoEDoNotModify,
		NativeNetworkID:   nativeID,
		TagNetworkIDs:     tagIDs,
		UntagNetworkIDs:   untagIDs,
		Dot1x:             omadabackend.Dot1xAuto,
		BandWidthCtrlType: omadabackend.BandWidthCtrlOff,
	}
	plan.ProfileID = "" // assigned on create
	plan.ProfileName = name
	plan.ProfileCreate = true
	return plan, profile, true, nil
}

// portEvidenceJSON renders one port row joined to its referenced LAN
// profile as a JSON string — the before/after evidence for port-profile
// applies. It works on an already-fetched collection set so an apply can
// reuse its plan read for the before evidence instead of re-fetching.
func portEvidenceJSON(ports []omadabackend.SwitchPort, profiles []omadabackend.LanProfile, nets []omadabackend.Network, switchMAC string, port int) (string, error) {
	netName := networkNameByID(nets)
	wantMAC := omadabackend.NormalizeMAC(switchMAC)
	for i := range ports {
		if ports[i].Port == port && omadabackend.NormalizeMAC(ports[i].SwitchMAC) == wantMAC {
			b, err := json.Marshal(portObservation(ports[i], profiles, netName))
			if err != nil {
				return "", err
			}
			return string(b), nil
		}
	}
	return "{}", nil
}

// portObservation joins one overview row to its referenced profile into the
// service-facing shape.
func portObservation(p omadabackend.SwitchPort, profiles []omadabackend.LanProfile, netName map[string]string) *OmadaSwitchPort {
	sp := &OmadaSwitchPort{
		Port:               p.Port,
		PortName:           p.PortName,
		SwitchMAC:          p.SwitchMAC,
		SwitchName:         p.SwitchName,
		ConnectedStatus:    p.ConnectedStatus,
		Disabled:           p.Disable,
		NetworkMode:        p.NetworkMode,
		NativeNetwork:      netName[p.NativeNetworkID],
		NativeBridgeVLAN:   p.NativeBridgeVLAN,
		NetworkTagsSetting: p.NetworkTagsSetting,
		ProfileID:          p.ProfileID,
		ProfileName:        p.ProfileName,
		ProfileOverride:    p.ProfileOverride,
		Tagged:             []string{},
	}
	if prof := findProfileByID(profiles, p.ProfileID); prof != nil {
		sp.Tagged = resolveNetworkIDs(prof.TagNetworkIDs, netName)
		if sp.NativeNetwork == "" {
			sp.NativeNetwork = netName[prof.NativeNetworkID]
		}
	}
	return sp
}

// derivePortProfileName builds a stable, agent-readable profile name from
// the request: the port's native name plus its tagged member count.
func derivePortProfileName(req OmadaPortProfileRequest) string {
	if len(req.Tagged) == 0 {
		return req.Native
	}
	return fmt.Sprintf("%s+trunk(%d)", req.Native, len(req.Tagged))
}

// resolveNetworkID resolves one network name (or a raw network ID) to its
// ID, refusing unknown and ambiguous names (a name that two declared
// networks share is an error, not a coin flip).
func resolveNetworkID(nets []omadabackend.Network, name string) (string, error) {
	ids, err := resolveNetworkIDList(nets, []string{name})
	if err != nil {
		return "", err
	}
	return ids[0], nil
}

// resolveNetworkIDList resolves a network name list to IDs (names
// case-insensitive; raw IDs pass through). Every member must resolve;
// duplicate names fail closed — binding a port to the "first" of several
// same-name networks would be a silent wrong-VLAN membership.
func resolveNetworkIDList(nets []omadabackend.Network, names []string) ([]string, error) {
	byName := make(map[string]string, len(nets))
	ambiguous := make(map[string][]string, len(nets))
	knownIDs := make(map[string]bool, len(nets))
	for _, n := range nets {
		knownIDs[n.ID] = true
		key := strings.ToLower(strings.TrimSpace(n.Name))
		if prev, dup := byName[key]; dup {
			if len(ambiguous[key]) == 0 {
				ambiguous[key] = append(ambiguous[key], prev)
			}
			ambiguous[key] = append(ambiguous[key], n.ID)
		} else {
			byName[key] = n.ID
		}
	}
	out := make([]string, 0, len(names))
	for _, name := range names {
		trimmed := strings.TrimSpace(name)
		if knownIDs[trimmed] {
			out = append(out, trimmed)
			continue
		}
		key := strings.ToLower(trimmed)
		if ids, ok := ambiguous[key]; ok {
			candidates := append([]string(nil), ids...)
			sort.Strings(candidates)
			return nil, fmt.Errorf("network name %q is ambiguous — %d declared networks share it (ids %s); address the network by its id", name, len(candidates), strings.Join(candidates, ", "))
		}
		id, ok := byName[key]
		if !ok {
			return nil, fmt.Errorf("network %q is not a declared LAN network on the site", name)
		}
		out = append(out, id)
	}
	return out, nil
}

// networkNameByID maps network IDs to display names for evidence output.
func networkNameByID(nets []omadabackend.Network) map[string]string {
	out := make(map[string]string, len(nets))
	for _, n := range nets {
		out[n.ID] = n.Name
	}
	return out
}

// resolveNetworkIDs renders an ID list as resolved names, falling back to
// the raw ID when a network is unknown.
func resolveNetworkIDs(ids []string, netName map[string]string) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if name, ok := netName[id]; ok && name != "" {
			out = append(out, name)
		} else {
			out = append(out, id)
		}
	}
	return out
}

// findProfileByID returns one profile by ID, or nil.
func findProfileByID(profiles []omadabackend.LanProfile, id string) *omadabackend.LanProfile {
	for i := range profiles {
		if profiles[i].ID == id {
			return &profiles[i]
		}
	}
	return nil
}

// serviceLanProfile converts one backend profile into the service shape
// with resolved names.
func serviceLanProfile(p omadabackend.LanProfile, netName map[string]string) *OmadaLanProfile {
	return &OmadaLanProfile{
		ID:                   p.ID,
		Flag:                 p.Flag,
		Name:                 p.Name,
		NativeNetwork:        netName[p.NativeNetworkID],
		TaggedNetworks:       resolveNetworkIDs(p.TagNetworkIDs, netName),
		Dot1x:                p.Dot1x,
		PortIsolationEnable:  p.PortIsolationEnable,
		SpanningTreeEnable:   p.SpanningTreeEnable,
		LoopbackDetectEnable: p.LoopbackDetectEnable,
	}
}

func idInList(ids []string, id string) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

// OmadaACLApplyRequest describes a desired ACL change on the site: the
// action to take between each From endpoint and each To endpoint
// (one-to-many and many-to-many supported). DryRun previews without
// mutating; PostAudit (default true) runs a targeted isolation audit after
// a real apply.
type OmadaACLApplyRequest struct {
	PolicyName string
	From       []string // source network names
	To         []string // destination network names
	Action     string   // "allow" or "deny"
	Scope      string   // "switch" (default) or "gateway"; "eap" is refused
	Protocols  []int    // IP protocols; empty means all
	DryRun     bool
	PostAudit  bool
}

// OmadaPostAudit is the targeted re-verification run after a real apply:
// one isolation finding per source endpoint, against the destination set.
type OmadaPostAudit struct {
	Status   string               `json:"status"`
	Summary  string               `json:"summary"`
	Findings []models.CheckResult `json:"findings,omitempty"`
}

// OmadaACLApplyResult is the structured outcome of an apply with
// before/after evidence and the post-apply audit. FromCIDRs/ToCIDRs and the
// gateway slices are in request order of the endpoints.
type OmadaACLApplyResult struct {
	DryRun       bool            `json:"dry_run"`
	Outcome      string          `json:"outcome"` // "created" | "enabled" | "unchanged"
	RuleID       string          `json:"rule_id,omitempty"`
	RuleName     string          `json:"rule_name,omitempty"`
	Scope        string          `json:"scope"`
	FromCIDRs    []string        `json:"from_cidrs"`
	ToCIDRs      []string        `json:"to_cidrs"`
	FromGateways []string        `json:"from_gateways,omitempty"`
	ToGateways   []string        `json:"to_gateways,omitempty"`
	Before       string          `json:"before"`
	After        string          `json:"after"`
	PostAudit    *OmadaPostAudit `json:"post_audit,omitempty"`
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

	siteID := site.EffectiveID()
	rules, err := client.GetACLRules(ctx, siteID)
	if err != nil {
		return nil, fmt.Errorf("fetching ACL rules: %w", err)
	}
	gwRules, err := client.GetGatewayACLRules(ctx, siteID)
	if err != nil {
		return nil, fmt.Errorf("fetching gateway ACL rules: %w", err)
	}
	all := append(rules, gwRules...)
	if nets, nerr := client.GetNetworks(ctx, siteID); nerr == nil {
		omadabackend.ResolveRules(all, nets)
	}

	out := make([]OmadaACLRule, 0, len(all))
	for _, r := range all {
		out = append(out, OmadaACLRule{
			ID:         r.ID,
			Name:       r.Name,
			Enabled:    r.Status,
			Policy:     r.Policy.String(),
			Protocols:  omadabackend.ProtocolsLabel(r.Protocols),
			SourceType: r.SourceType.String(),
			SourceName: r.SourceName,
			DestType:   r.DestType.String(),
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
	Site               string            `json:"site"`
	ControllerVersion  string            `json:"controller_version"`
	ControllerCategory string            `json:"controller_category,omitempty"`
	Devices            []serviceDevice   `json:"devices"`
	NetworkGateways    map[string]string `json:"network_gateways,omitempty"`
	ACLScopes          []serviceACLScope `json:"acl_scopes,omitempty"`
	ClientCount        int               `json:"client_count"`
	Warnings           []string          `json:"warnings,omitempty"`
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
		Warnings:           snap.Warnings,
		NetworkGateways:    map[string]string{},
	}
	specInv := omadabackend.BuildSpecInventory(snap)
	inv.NetworkGateways = specInv.NetworkGateways
	for _, d := range specInv.Devices {
		inv.Devices = append(inv.Devices, serviceDevice{
			Type:     d.Type,
			Name:     d.Name,
			Model:    d.Model,
			IP:       d.IP,
			Firmware: d.Firmware,
			Upgrade:  d.Upgrade,
			Networks: d.Networks,
		})
	}
	for _, sc := range specInv.ACLScopes {
		inv.ACLScopes = append(inv.ACLScopes, serviceACLScope{Scope: sc.Scope, RuleCount: sc.RuleCount})
	}
	return inv, nil
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

// Plan previews the difference between the controller's current ACL rules
// and a proposed intent spec. It is read-only: nothing is applied. The
// proposal is validated before any controller request is made.
func (s *OmadaService) Plan(ctx context.Context, opts OmadaOptions, proposedYAML string) (*OmadaPlan, error) {
	proposed, err := intent.ParseSpec([]byte(proposedYAML))
	if err != nil {
		return nil, err
	}

	client, site, err := s.session(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer client.Logout(ctx) //nolint:errcheck

	nets, err := client.GetNetworks(ctx, site.EffectiveID())
	if err != nil {
		return nil, fmt.Errorf("fetching networks: %w", err)
	}
	rules, err := client.GetACLRules(ctx, site.EffectiveID())
	if err != nil {
		return nil, fmt.Errorf("fetching ACL rules: %w", err)
	}
	gwRules, err := client.GetGatewayACLRules(ctx, site.EffectiveID())
	if err != nil {
		return nil, fmt.Errorf("fetching gateway ACL rules: %w", err)
	}

	current := omadabackend.PoliciesFromRules(append(rules, gwRules...), nets)
	plan := diffPolicies(current, proposed.Policies, networkNames(proposed.Networks))
	plan.Site = site.Name
	plan.ProposedSite = proposed.Site
	return plan, nil
}

// ApplyACL applies a single desired ACL change through the registered
// provider's mutation surface. A real (non-dry-run) apply that changes the
// controller is followed by a targeted isolation audit against the same
// endpoints, returned as post_audit evidence.
func (s *OmadaService) ApplyACL(ctx context.Context, opts OmadaOptions, req OmadaACLApplyRequest) (*OmadaACLApplyResult, error) {
	applier, err := s.newApplier()
	if err != nil {
		return nil, err
	}
	// Normalise endpoint sets once, before the provider and the post-audit
	// spec both consume them.
	req.From = dedupeNames(req.From)
	req.To = dedupeNames(req.To)
	res, err := applier.ApplyACL(ctx, providers.ACLApplyRequest{
		PolicyName: req.PolicyName,
		From:       req.From,
		To:         req.To,
		Action:     req.Action,
		Scope:      req.Scope,
		Protocols:  req.Protocols,
		DryRun:     req.DryRun,
	}, providers.ImportOptions{
		Host:          opts.Host,
		ClientID:      opts.ClientID,
		ClientSecret:  opts.ClientSecret,
		Site:          opts.Site,
		SkipTLSVerify: opts.SkipTLSVerify,
		CACertPath:    opts.CACertPath,
	})
	if err != nil {
		return nil, err
	}
	out := &OmadaACLApplyResult{
		DryRun:       res.DryRun,
		Outcome:      res.Outcome,
		RuleID:       res.RuleID,
		RuleName:     res.RuleName,
		Scope:        res.Scope,
		FromCIDRs:    res.FromCIDRs,
		ToCIDRs:      res.ToCIDRs,
		FromGateways: res.FromGateways,
		ToGateways:   res.ToGateways,
		Before:       res.Before,
		After:        res.After,
	}
	if !res.DryRun && res.Outcome != "unchanged" && req.PostAudit {
		out.PostAudit = s.runPostAudit(ctx, req, res)
	}
	return out, nil
}

// newApplier returns the registered Omada provider's ACLApplier. The registry
// lookup enforces the optional-interface contract: a provider that cannot
// mutate is refused with a clear error.
func (s *OmadaService) newApplier() (providers.ACLApplier, error) {
	p := providers.Get(omadaprovider.ProviderName)
	applier, ok := p.(providers.ACLApplier)
	if !ok {
		return nil, fmt.Errorf("provider %q does not implement ACL mutation", omadaprovider.ProviderName)
	}
	return applier, nil
}

// runPostAudit builds a targeted spec for the changed endpoints and runs the
// isolation assertions through the configured audit engine: one assertion
// per source endpoint, each checked against the full comma-joined
// destination set. The gateways from the apply result are mandatory:
// without them runIsolation has no target to ping and the audit is
// unverifiable by construction.
func (s *OmadaService) runPostAudit(ctx context.Context, req OmadaACLApplyRequest, res *providers.ACLApplyResult) *OmadaPostAudit {
	// A spec may not declare duplicate network names, so merge the endpoint
	// sets; From endpoints come first (the assertions name them).
	networks := make([]intent.Network, 0, len(req.From)+len(req.To))
	added := make(map[string]bool, len(req.From)+len(req.To))
	add := func(n intent.Network) {
		key := strings.ToLower(n.Name)
		if added[key] {
			return
		}
		added[key] = true
		networks = append(networks, n)
	}
	destNames := strings.Join(req.To, ",")
	assertions := make([]intent.Assertion, 0, len(req.From))
	for i, name := range req.From {
		add(intent.Network{Name: name, CIDR: at(res.FromCIDRs, i), Gateway: at(res.FromGateways, i)})
		assertions = append(assertions, intent.Assertion{Type: "isolation", From: name, To: destNames, Expect: req.Action})
	}
	for i, name := range req.To {
		add(intent.Network{Name: name, CIDR: at(res.ToCIDRs, i), Gateway: at(res.ToGateways, i)})
	}
	spec := &intent.Spec{Version: 1, Site: "post-mutation", Networks: networks, Assertions: assertions}
	if s.PostAudit == nil {
		return &OmadaPostAudit{Status: string(models.StatusError), Summary: "post-mutation audit unavailable"}
	}
	report, err := s.PostAudit(ctx, spec)
	if err != nil {
		return &OmadaPostAudit{Status: string(models.StatusError), Summary: fmt.Sprintf("post-mutation audit failed: %v", err)}
	}
	findings := make([]models.CheckResult, 0, len(assertions))
	for _, f := range report.Findings {
		if f.CheckType == "isolation" {
			findings = append(findings, f)
		}
	}
	if len(findings) == 0 {
		return &OmadaPostAudit{Status: string(models.StatusError), Summary: "post-mutation audit returned no isolation finding"}
	}
	return &OmadaPostAudit{
		Status:   string(models.ComputeOverallStatus(findings)),
		Summary:  fmt.Sprintf("post-mutation audit: %d isolation check(s), overall %s", len(findings), models.ComputeOverallStatus(findings)),
		Findings: findings,
	}
}

// at returns s[i] when in range, "" otherwise: result slices are
// positional against the request endpoints, and an absent value must not
// crash the post-audit.
func at(s []string, i int) string {
	if i >= 0 && i < len(s) {
		return s[i]
	}
	return ""
}

// dedupeNames drops empty and repeated endpoint names (case-insensitive,
// matching the controller's name resolution), keeping the first spelling.
func dedupeNames(names []string) []string {
	seen := make(map[string]bool, len(names))
	out := names[:0]
	for _, n := range names {
		key := strings.ToLower(strings.TrimSpace(n))
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, strings.TrimSpace(n))
	}
	return out
}

// networkNames returns the declared network names of a spec.
func networkNames(networks []intent.Network) []string {
	names := make([]string, 0, len(networks))
	for _, n := range networks {
		names = append(names, n.Name)
	}
	return names
}

// diffPolicies compares current controller policies against the proposed
// ones. Policies match on the from/to pair; a single pair with a different
// action on each side is a change. Multiple rules for the same pair are
// matched by action counts so no rule is silently dropped. Warnings flag
// proposal endpoints that are not declared in the proposed spec's networks.
func diffPolicies(current, proposed []intent.Policy, declaredNetworks []string) *OmadaPlan {
	declared := make(map[string]bool, len(declaredNetworks))
	for _, n := range declaredNetworks {
		declared[n] = true
	}

	plan := &OmadaPlan{CurrentRules: len(current), ProposedRules: len(proposed)}

	currentGroups := groupPoliciesByKey(current)
	proposedGroups := groupPoliciesByKey(proposed)

	for _, key := range sortedKeys(union(currentGroups, proposedGroups)) {
		cur := currentGroups[key]
		prop := proposedGroups[key]
		switch {
		case len(prop) == 0:
			for _, cp := range cur {
				plan.ToRemove = append(plan.ToRemove, diffFromPolicy(cp, "", cp.Action))
			}
		case len(cur) == 1 && len(prop) == 1 && cur[0].Action != prop[0].Action:
			plan.ToChange = append(plan.ToChange, diffFromPolicy(prop[0], cur[0].Action, prop[0].Action))
			warnIfUndeclared(prop[0], declared, &plan.Warnings)
		default:
			curCounts := countActions(cur)
			propCounts := countActions(prop)
			for action, c := range curCounts {
				p := propCounts[action]
				for i := 0; i < min(c, p); i++ {
					plan.Unchanged = append(plan.Unchanged, diffFromPolicy(policyWithAction(prop, action), "", action))
				}
				for i := 0; i < c-p; i++ {
					plan.ToRemove = append(plan.ToRemove, diffFromPolicy(policyWithAction(cur, action), "", action))
				}
				for i := 0; i < p-c; i++ {
					plan.ToAdd = append(plan.ToAdd, diffFromPolicy(policyWithAction(prop, action), "", action))
					warnIfUndeclared(policyWithAction(prop, action), declared, &plan.Warnings)
				}
			}
			for action, p := range propCounts {
				if curCounts[action] > 0 {
					continue
				}
				for i := 0; i < p; i++ {
					plan.ToAdd = append(plan.ToAdd, diffFromPolicy(policyWithAction(prop, action), "", action))
					warnIfUndeclared(policyWithAction(prop, action), declared, &plan.Warnings)
				}
			}
		}
	}
	return plan
}

// groupPoliciesByKey indexes policies by their from|to pair, preserving all
// entries (including duplicates).
func groupPoliciesByKey(policies []intent.Policy) map[string][]intent.Policy {
	groups := make(map[string][]intent.Policy, len(policies))
	for _, p := range policies {
		key := policyKey(p)
		groups[key] = append(groups[key], p)
	}
	return groups
}

func policyKey(p intent.Policy) string {
	return p.From + "|" + p.To
}

// countActions tallies how many policies use each action within a group.
func countActions(policies []intent.Policy) map[string]int {
	counts := make(map[string]int, len(policies))
	for _, p := range policies {
		counts[p.Action]++
	}
	return counts
}

func policyWithAction(policies []intent.Policy, action string) intent.Policy {
	for _, p := range policies {
		if p.Action == action {
			return p
		}
	}
	return policies[0]
}

func union(a, b map[string][]intent.Policy) map[string]bool {
	keys := make(map[string]bool, len(a)+len(b))
	for k := range a {
		keys[k] = true
	}
	for k := range b {
		keys[k] = true
	}
	return keys
}

func sortedKeys(keys map[string]bool) []string {
	out := make([]string, 0, len(keys))
	for k := range keys {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// warnIfUndeclared appends a warning when a proposal endpoint is not a
// declared network in the proposed spec.
func warnIfUndeclared(p intent.Policy, declared map[string]bool, warnings *[]string) {
	if p.From != "" && !declared[p.From] {
		*warnings = append(*warnings,
			fmt.Sprintf("policy %q: from %q is not a declared network in the proposed spec", p.Name, p.From))
	}
	if p.To != "" && !declared[p.To] {
		*warnings = append(*warnings,
			fmt.Sprintf("policy %q: to %q is not a declared network in the proposed spec", p.Name, p.To))
	}
}

func diffFromPolicy(p intent.Policy, currentAction, proposedAction string) OmadaPolicyDiff {
	if currentAction == "" || currentAction == proposedAction {
		return OmadaPolicyDiff{Name: p.Name, From: p.From, To: p.To, Action: proposedAction}
	}
	return OmadaPolicyDiff{Name: p.Name, From: p.From, To: p.To, CurrentAction: currentAction, ProposedAction: proposedAction}
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
