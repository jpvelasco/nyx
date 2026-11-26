package service

import (
	"errors"
	"strconv"
	"strings"

	fw "github.com/jpvelasco/nyx/internal/providers/opnsense"
)

func (req OpnsenseFilterRequest) scoped() bool {
	return req.SourcePort != "" || req.DestinationPort != "" || req.Direction != "" || req.AddressFamily != ""
}

var filterFamilies = map[string]string{"": "inet", "ipv4": "inet", "ipv6": "inet6", "dual": "inet46"}

func (req OpnsenseFilterRequest) validateSelectors() error {
	if req.Kind != "" && !strings.EqualFold(req.Kind, "filter") && !strings.EqualFold(req.Kind, "alias") {
		return errors.New("kind must be filter or alias")
	}
	if !req.scoped() {
		return nil
	}
	if (req.Kind != "" && !strings.EqualFold(req.Kind, "filter")) || req.Delete {
		return errors.New("service selectors require a filter create or update")
	}
	if req.Source == "" || req.Destination == "" || req.Interface == "" {
		return errors.New("a scoped filter needs an interface, source and destination")
	}
	if _, ok := filterFamilies[req.AddressFamily]; !ok {
		return errors.New("address_family must be ipv4, ipv6 or dual")
	}
	switch req.Direction {
	case "", "in", "out", "any":
	default:
		return errors.New("direction must be in, out or any")
	}
	if req.SourcePort == "" && req.DestinationPort == "" {
		return nil
	}
	switch strings.ToLower(req.Protocol) {
	case "tcp", "udp", "tcp/udp":
	default:
		return errors.New("port selectors require TCP, UDP or TCP/UDP")
	}
	for _, port := range []string{req.SourcePort, req.DestinationPort} {
		if port != "" && !filterPort(port) {
			return errors.New("a port selector must be a port number or an ascending numeric range")
		}
	}
	return nil
}

func filterPort(raw string) bool {
	lo, hi, ranged := strings.Cut(raw, "-")
	first, err := strconv.ParseUint(lo, 10, 16)
	if err != nil || first == 0 {
		return false
	}
	if !ranged {
		return true
	}
	last, err := strconv.ParseUint(hi, 10, 16)
	return err == nil && last >= first
}

func (req OpnsenseFilterRequest) write() fw.FilterWrite {
	description := req.Description
	if req.scoped() && description == "" {
		description = req.Name
	}
	return fw.FilterWrite{
		Action: firstNonEmptySvc(req.Action, "block"), Interface: req.Interface,
		Protocol: req.Protocol, Source: req.Source, Destination: req.Destination,
		SourcePort: req.SourcePort, DestPort: req.DestinationPort, Direction: req.Direction,
		IPProtocol: filterFamilies[req.AddressFamily], Description: description, Enabled: req.Enabled,
	}
}

// Find an explicit target first. Without one, compare the complete request to
// the create defaults. A rule with extra selectors cannot prove equivalence.
func (req OpnsenseFilterRequest) findRule(rules []fw.FirewallRule) (fw.FirewallRule, bool, error) {
	if !req.scoped() {
		r, ok := fw.FindFilterRule(rules, req.UUID, req.Name)
		return r, ok, nil
	}
	var found fw.FirewallRule
	w := req.write()
	label := firstNonEmptySvc(req.Name, req.Description)
	for _, r := range rules {
		match := false
		if req.UUID != "" {
			match = strings.EqualFold(req.UUID, r.RuleUUID)
		} else {
			match = (label != "" && strings.EqualFold(r.Label, label)) || fw.ExactFilterMatch(r, w)
		}
		if !match {
			continue
		}
		if found.RuleUUID != "" || r.RuleUUID == "" {
			return found, false, errors.New("multiple or unidentified filter rules match the request; select a UUID")
		}
		if r.ExtraConditions {
			return found, false, errors.New("selected filter rule has additional enforcement conditions; review it before making changes")
		}
		// OPNsense retains omitted fields on update. Ensure the preview and the
		// saved rule agree before changing an explicitly selected rule.
		for _, selector := range []struct{ requested, observed, fallback string }{
			{req.SourcePort, r.SourcePort, "any"}, {req.DestinationPort, r.DestPort, "any"},
			{req.Direction, r.Direction, "in"}, {req.Protocol, r.Protocol, "any"},
			{req.AddressFamily, r.IPProtocol, "inet"},
		} {
			if selector.requested == "" && selector.observed != "" && !strings.EqualFold(selector.observed, selector.fallback) {
				return found, false, errors.New("a selected rule already restricts an omitted selector; specify its ports, direction, protocol and address family explicitly")
			}
		}
		found = r
	}
	if req.UUID != "" && found.RuleUUID == "" {
		return found, false, errors.New("selected filter UUID not found")
	}
	return found, found.RuleUUID != "", nil
}
