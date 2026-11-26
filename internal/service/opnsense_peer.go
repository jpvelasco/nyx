package service

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strings"

	"github.com/jpvelasco/nyx/internal/providers/opnsense"
)

// WireGuardPeerRequest describes a selected peer change with public metadata only.
type WireGuardPeerRequest struct {
	Action, UUID, Name string
	AllowedNetworks    []string
	Enabled            *bool
}

// WireGuardPeerPlan records the configured peer and each completed revocation stage.
type WireGuardPeerPlan struct {
	Action          string   `json:"action"`
	UUID            string   `json:"uuid,omitempty"`
	Name            string   `json:"name,omitempty"`
	CurrentNetworks []string `json:"current_networks,omitempty"`
	DesiredNetworks []string `json:"desired_networks,omitempty"`
	Overlaps        []string `json:"overlapping_peer_uuids,omitempty"`
	Unverified      []string `json:"unverified_peer_uuids,omitempty"`
	Outcome         string   `json:"outcome"`
	OperatorAction  bool     `json:"operator_action,omitempty"`
	ConfigChanged   bool     `json:"config_changed,omitempty"`
	Reloaded        bool     `json:"reloaded,omitempty"`
	Verified        bool     `json:"verified,omitempty"`
	ServiceRunning  *bool    `json:"service_running,omitempty"`
}

func peerPrefixes(fields []string) ([]netip.Prefix, error) {
	unique := map[netip.Prefix]bool{}
	var result []netip.Prefix
	for _, s := range fields {
		for raw := range strings.SplitSeq(s, ",") {
			p, err := netip.ParsePrefix(strings.TrimSpace(raw))
			if err != nil || p != p.Masked() {
				return nil, errors.New("allowed networks must be canonical IPv4 or IPv6 prefixes")
			}
			if !unique[p] {
				unique[p] = true
				result = append(result, p)
			}
		}
	}
	slices.SortFunc(result, func(a, b netip.Prefix) int { return strings.Compare(a.String(), b.String()) })
	return result, nil
}
func prefixStrings(prefixes []netip.Prefix) []string {
	out := make([]string, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, p.String())
	}
	return out
}
func intersects(left, right []netip.Prefix) bool {
	for _, a := range left {
		for _, b := range right {
			if a.Overlaps(b) {
				return true
			}
		}
	}
	return false
}

// PlanWireGuardPeer previews a selected peer change. Only exact-UUID revocation can be executed through Nyx.
func (s *OpnsenseService) PlanWireGuardPeer(ctx context.Context, opts OpnsenseOptions, r WireGuardPeerRequest) (*WireGuardPeerPlan, error) {
	plan := &WireGuardPeerPlan{Action: r.Action, UUID: r.UUID, Name: r.Name, Outcome: "planned"}
	switch r.Action {
	case "create":
		if r.UUID != "" || r.Name == "" || len(r.AllowedNetworks) == 0 {
			return nil, errors.New("create preview requires a name and allowed networks")
		}
		plan.OperatorAction = true
	case "update", "toggle", "remove":
		if !opnsense.ValidPeerUUID(r.UUID) {
			return nil, errors.New("select one peer by UUID")
		}
		if r.Action == "toggle" && r.Enabled == nil {
			return nil, errors.New("toggle requires an explicit desired enabled state")
		}
		if r.Action == "update" && len(r.AllowedNetworks) == 0 {
			return nil, errors.New("update preview requires allowed networks")
		}
		plan.OperatorAction = r.Action == "update" || r.Action == "toggle" && *r.Enabled
	default:
		return nil, errors.New("action must be create, update, toggle or remove")
	}
	if (r.Action == "remove" || r.Action == "toggle") && (len(r.AllowedNetworks) > 0 || r.Name != "") {
		return nil, errors.New("revocation accepts only the selected peer and action")
	}
	if r.Action != "toggle" && r.Enabled != nil {
		return nil, errors.New("enabled applies only to toggle")
	}
	desired, err := peerPrefixes(r.AllowedNetworks)
	if err != nil {
		return nil, err
	}
	plan.DesiredNetworks = prefixStrings(desired)
	peers, err := s.client(opts).GetWireGuardClients(ctx)
	if err != nil {
		return nil, errors.New("reading peers: " + readAccess(err))
	}
	matched := false
	for _, p := range peers {
		selected := r.UUID != "" && strings.EqualFold(r.UUID, p.UUID)
		if r.Action == "create" && r.Name == p.Name {
			return nil, errors.New("a peer already uses this name; select it by UUID to edit")
		}
		prefixes, parseErr := peerPrefixes(strings.FieldsFunc(strings.TrimSpace(p.TunnelAddress+","+p.AllowedIPs), func(c rune) bool { return c == ',' || c == ' ' }))
		if selected {
			if matched {
				return nil, errors.New("peer selection is ambiguous")
			}
			matched = true
			plan.Name = p.Name
			if parseErr != nil {
				plan.Unverified = append(plan.Unverified, p.UUID)
			}
			plan.CurrentNetworks = prefixStrings(prefixes)
			if r.Action == "toggle" && p.Enabled == *r.Enabled || r.Action == "update" && slices.Equal(plan.DesiredNetworks, plan.CurrentNetworks) {
				plan.Outcome = "unchanged"
			}
			continue
		}
		if len(desired) == 0 {
			continue
		}
		if parseErr != nil || len(prefixes) == 0 {
			plan.Unverified = append(plan.Unverified, p.UUID)
			continue
		}
		if intersects(prefixes, desired) {
			plan.Overlaps = append(plan.Overlaps, p.UUID)
		}
	}
	if r.Action != "create" && !matched {
		if r.Action != "remove" {
			return nil, errors.New("selected peer does not exist")
		}
		plan.Outcome = "absent"
	}
	if len(plan.Overlaps) > 0 {
		plan.Outcome = "overlap"
	}
	if len(plan.Unverified) > 0 && plan.Outcome == "planned" {
		plan.Outcome = "unverified"
	}
	return plan, nil
}

// RevokeWireGuardPeer re-reads intent before an exact disable or removal, then verifies the stored peer and service.
func (s *OpnsenseService) RevokeWireGuardPeer(ctx context.Context, opts OpnsenseOptions, r WireGuardPeerRequest, dryRun bool) (*WireGuardPeerPlan, error) {
	plan, err := s.PlanWireGuardPeer(ctx, opts, r)
	if err != nil || dryRun {
		return plan, err
	}
	if r.Action != "remove" && (r.Action != "toggle" || r.Enabled == nil || *r.Enabled) {
		return plan, errors.New("enrollment, access edits and reactivation require operator administration")
	}
	if plan.Outcome == "absent" || plan.Outcome == "unchanged" {
		plan.Verified = true
		status, err := s.client(opts).GetWireGuardStatus(ctx)
		if err != nil {
			return plan, errors.New("peer configuration verified; service status unavailable: " + readAccess(err))
		}
		plan.ServiceRunning = &status.Running
		return plan, nil
	}
	c := s.client(opts)
	if err := c.RevokeWireGuardPeer(ctx, r.UUID, r.Action == "remove"); err != nil {
		return plan, errors.New("peer revocation unconfirmed: " + readAccess(err))
	}
	plan.ConfigChanged = true
	if err := c.ReloadWireGuard(ctx); err != nil {
		return plan, errors.New("configuration saved; WireGuard reload unconfirmed: " + readAccess(err))
	}
	plan.Reloaded = true
	current, err := s.PlanWireGuardPeer(ctx, opts, r)
	if err != nil {
		return plan, err
	}
	plan.Verified = current.Outcome == "absent" || current.Outcome == "unchanged"
	if !plan.Verified {
		return plan, errors.New("peer revocation readback did not match")
	}
	status, err := c.GetWireGuardStatus(ctx)
	if err != nil {
		return plan, errors.New("peer revocation verified; service status unavailable: " + readAccess(err))
	}
	plan.ServiceRunning = &status.Running
	plan.Outcome = "revoked"
	return plan, nil
}
