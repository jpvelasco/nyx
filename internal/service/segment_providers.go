package service

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"

	fw "github.com/jpvelasco/nyx/internal/providers/opnsense"
)

type segmentProviders struct {
	ctx       context.Context
	omada     OmadaOptions
	firewall  OpnsenseOptions
	req       SegmentRequest
	iface     string
	preview   bool
	audit     segmentAudit
	switchAPI *OmadaService
	router    *OpnsenseService
}

func (e *segmentProviders) operations() []segmentOperation {
	step := func(name, owner, detail string, deps []string, do func(bool) (string, error)) segmentOperation {
		return segmentOperation{SegmentStep{Name: name, Owner: owner, Detail: detail, DependsOn: deps}, do}
	}
	ops := []segmentOperation{
		step("management_path", "opnsense", "Observe the protected network and existing interface rules.", nil, e.preflight),
		step("vlan_device", "opnsense", "Create or reuse the exact parent, tag and role.", []string{"management_path"}, e.vlan),
		step("assignment", "opnsense", "Assign the VLAN and static gateway. Older firewalls require interface assignment in the GUI.", []string{"vlan_device"}, e.assignment),
		step("deny_management", "opnsense", "Block incoming IPv4 traffic from the segment to management.", []string{"assignment"}, func(d bool) (string, error) { return e.filter("deny_management", d) }),
		step("permit_dns", "opnsense", "Permit TCP and UDP port 53 only to the requested resolver.", []string{"deny_management"}, func(d bool) (string, error) { return e.filter("permit_dns", d) }),
		step("dhcp_pool", "opnsense", "Configure the selected Dnsmasq pool. Kea pools require operator configuration.", []string{"permit_dns"}, e.dhcp),
		step("switch_vlan", "omada", "Create the VLAN-only network in the selected site. Existing routed LANs and duplicate tags require review.", []string{"permit_dns"}, e.lan),
	}
	verificationDeps := []string{"dhcp_pool", "switch_vlan"}
	if e.req.SSID != "" {
		verificationDeps = append(verificationDeps, "wireless")
		ops = append(ops, step("wireless", "omada", "Verify the selected secured SSID and VLAN. Provision wireless credentials using the controller.", []string{"switch_vlan", "dhcp_pool"}, e.wireless))
	}
	return append(ops, step("source_verification", "source_probe", "Check the declared source probe's active lease, resolver and management isolation using the operator's verification spec.", verificationDeps, e.verify))
}

func (e *segmentProviders) preflight(bool) (string, error) {
	rows, err := e.router.ListInterfaces(e.ctx, e.firewall)
	if err != nil {
		return "", err
	}
	r := e.req
	mgmt, _ := netip.ParsePrefix(r.Management)
	segment, _ := netip.ParsePrefix(r.Gateway)
	found := false
	for _, row := range rows {
		addr, err := netip.ParseAddr(row.IP)
		if err != nil {
			continue
		}
		observed := netip.PrefixFrom(addr, row.Subnet).Masked()
		if observed.Overlaps(segment) && (observed != segment.Masked() || addr != segment.Addr() || !strings.EqualFold(row.Description, r.Role)) {
			return "", errors.New("segment overlaps an existing interface network")
		}
		if observed == mgmt {
			found = true
		}
	}
	if !found {
		return "", errors.New("protected management prefix was not found on the selected firewall")
	}
	if err := e.checkRules(rows); err != nil {
		return "", err
	}
	// A colliding controller VLAN must be detected before creating the routed interface.
	if _, err := e.lan(true); err != nil {
		return "", err
	}
	return "verified", nil
}

// Interface groups may also match a new VLAN. Treat unrecognized group membership and
// floating pass rules as unknown unless the rule matches the exact DNS exception.
func (e *segmentProviders) checkRules(rows []OpnsenseInterface) error {
	known := map[string]bool{}
	for _, row := range rows {
		if !strings.EqualFold(row.Description, e.req.Role) {
			known[row.Name] = true
		}
	}
	rules, err := e.router.client(e.firewall).GetFirewallRules(e.ctx)
	if err != nil {
		return err
	}
	source, _ := netip.ParsePrefix(e.req.Gateway)
	for _, rule := range rules {
		if rule.Disabled && !rule.EnabledUnknown || strings.EqualFold(rule.Action, "block") || strings.EqualFold(rule.Action, "reject") {
			continue
		}
		relevant := len(rule.Interface) == 0
		for _, name := range rule.Interface {
			if name == e.iface || !known[name] || rule.ExtraConditions {
				relevant = true
			}
		}
		if !relevant {
			continue
		}
		if rule.EnabledUnknown || !strings.EqualFold(rule.Action, "pass") {
			return errors.New("could not verify state or action of a rule covering the segment")
		}
		if len(rule.Interface) == 1 && !rule.ExtraConditions {
			want := e.filterRequest("permit_dns")
			want.Interface = rule.Interface[0]
			if fw.ExactFilterMatch(rule, want.write()) {
				continue
			}
		}
		// A positive, literal source outside the segment is disjoint. Extra conditions may negate it.
		if prefix, err := netip.ParsePrefix(rule.Source); !rule.ExtraConditions && err == nil && !prefix.Overlaps(source) {
			continue
		}
		return errors.New("an existing pass rule may cover the new segment; review interface groups, floating rules and precedence")
	}
	return nil
}
func (e *segmentProviders) vlan(dry bool) (string, error) {
	r := e.req
	v, err := e.router.ApplyVLAN(e.ctx, e.firewall, OpnsenseVLANRequest{Kind: "vlan", Parent: r.Parent, Tag: r.Tag, Description: r.Role, CreateOnly: true}, dry)
	if err != nil {
		return "", err
	}
	return v.Outcome, nil
}
func (e *segmentProviders) assignment(dry bool) (string, error) {
	r := e.req
	v, err := e.router.ApplyVLAN(e.ctx, e.firewall, OpnsenseVLANRequest{Kind: "assignment", Parent: r.Parent, Tag: r.Tag, Address: r.Gateway, Description: r.Role}, dry)
	if err != nil {
		return "", err
	}
	if v.Outcome == "unchanged" {
		if v.UUID == "" {
			return "", errors.New("assigned interface identifier is unavailable")
		}
		e.iface = v.UUID
	}
	return v.Outcome, nil
}
func (e *segmentProviders) filterRequest(name string) OpnsenseFilterRequest {
	r := e.req
	p, _ := netip.ParsePrefix(r.Gateway)
	req := OpnsenseFilterRequest{CreateOnly: true, Name: "nyx-" + r.Role + "-" + name, Action: "block", Protocol: "any", Direction: "in", AddressFamily: "ipv4", Source: p.Masked().String(), Destination: r.Management, Interface: e.iface, Enabled: true}
	if name == "permit_dns" {
		req.Action = "pass"
		req.Protocol = "tcp/udp"
		req.Destination = r.Resolver
		req.DestinationPort = "53"
	}
	return req
}
func (e *segmentProviders) filter(name string, dry bool) (string, error) {
	rows, err := e.router.ListInterfaces(e.ctx, e.firewall)
	if err != nil {
		return "", err
	}
	if err = e.checkRules(rows); err != nil {
		return "", err
	}
	v, err := e.router.ApplyFilter(e.ctx, e.firewall, e.filterRequest(name), dry)
	if err != nil {
		return "", err
	}
	return v.Outcome, nil
}
func (e *segmentProviders) dhcp(dry bool) (string, error) {
	r := e.req
	v, err := e.router.ApplyDHCP(e.ctx, e.firewall, OpnsenseDHCPRequest{CreateOnly: true, Backend: "dnsmasq", Kind: "range", Interface: e.iface, Start: r.Start, End: r.End}, dry)
	if err != nil {
		return "", err
	}
	return v.Outcome, nil
}
func (e *segmentProviders) lan(dry bool) (string, error) {
	r := e.req
	v, err := e.switchAPI.ApplyLAN(e.ctx, e.omada, OmadaLANRequest{CreateOnly: true, Name: r.Role, VLAN: r.Tag}, dry)
	if err != nil {
		return "", err
	}
	return v.Outcome, nil
}
func (e *segmentProviders) wireless(bool) (string, error) {
	inv, err := e.switchAPI.ListSSIDs(e.ctx, e.omada)
	if err != nil {
		return "", err
	}
	n := 0
	for _, ssid := range inv.SSIDs {
		if ssid.SSID != e.req.SSID {
			continue
		}
		n++
		if !ssid.Enabled || ssid.VLANID != e.req.Tag || !slices.Contains([]string{"wpa2", "wpa3", "wpa2/wpa3", "wpa2-psk", "wpa3-sae"}, strings.ToLower(ssid.Security)) {
			return "manual", nil
		}
	}
	if n != 1 {
		return "manual", nil
	}
	return "verified", nil
}
