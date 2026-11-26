package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
)

// OmadaUplinkInfo is one device uplink observation: which managed device
// (and port) the queried MAC is cabled into.
type OmadaUplinkInfo struct {
	MAC              string `json:"mac"`
	UplinkDeviceMAC  string `json:"uplink_device_mac,omitempty"`
	UplinkDeviceName string `json:"uplink_device_name,omitempty"`
	UplinkDevicePort string `json:"uplink_device_port,omitempty"`
	LinkSpeed        int    `json:"link_speed"`
	Duplex           int    `json:"duplex"`
	LinkSpeedSource  string `json:"link_speed_source"` // always "configured"; negotiated speed is not on the Open API
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
	LinkSpeed          int      `json:"link_speed"`
	Duplex             int      `json:"duplex"`
	LinkSpeedSource    string   `json:"link_speed_source"` // always "configured"; negotiated speed is not on the Open API
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
	Revision       string                  `json:"revision"`
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
	VerifyClientMAC  string   `json:"verify_client_mac,omitempty"`
	ExpectedRevision string   `json:"expected_revision,omitempty"`
	SwitchMAC        string   `json:"switch_mac"`
	Port             int      `json:"port"`
	Native           string   `json:"native"` // network name (required)
	Tagged           []string `json:"tagged,omitempty"`
	ProfileName      string   `json:"profile_name,omitempty"` // optional; derived when empty
}

// OmadaPortProfileApplyResult is the structured outcome of a port-profile
// apply with before/after evidence (the port row joined to its referenced
// LAN profile).
type OmadaPortProfileApplyResult struct {
	Verification  *PortVerification `json:"verification,omitempty"`
	DryRun        bool              `json:"dry_run"`
	Outcome       string            `json:"outcome"` // "unchanged" | "bound" | "created_and_bound" (a dry run previews the real-apply outcome)
	SwitchMAC     string            `json:"switch_mac"`
	Port          int               `json:"port"`
	ProfileID     string            `json:"profile_id,omitempty"`
	ProfileName   string            `json:"profile_name,omitempty"`
	ProfileCreate bool              `json:"profile_create,omitempty"`
	Before        string            `json:"before"`
	After         string            `json:"after"`
	Warnings      []string          `json:"warnings,omitempty"`
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
			LinkSpeedSource:  omadabackend.LinkSpeedConfigured,
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
	plan, _, _, err := planPortFromState(site.EffectiveID(), req, ports, profiles, nets)
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
	plan, prof, create, err := planPortFromState(site.EffectiveID(), req, ports, profiles, nets)
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
		if req.ExpectedRevision != "" {
			res.Verification = verifyPortEvidence(ctx, client, siteID, req, ports, profiles, nets)
		}
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
	if req.ExpectedRevision != "" {
		res.Verification = verifyPortEvidence(ctx, client, siteID, req, afterPorts, afterProfiles, afterNets)
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
func planPortFromState(siteID string, req OmadaPortProfileRequest, ports []omadabackend.SwitchPort, profiles []omadabackend.LanProfile, nets []omadabackend.Network) (*OmadaPortPlan, *omadabackend.LanProfile, bool, error) {
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
	revision, err := portRevision(siteID, plan.Current, plan.CurrentProfile, nativeID, tagIDs)
	if err != nil {
		return nil, nil, false, err
	}
	plan.Revision = revision
	if req.ExpectedRevision != "" && req.ExpectedRevision != revision {
		return nil, nil, false, fmt.Errorf("port configuration changed since the plan; refresh the switch plan")
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

// portRevision binds the preview to its selected site, switch, port and effective
// configuration. It contains no credentials and is recomputed before a bind.
func portRevision(siteID string, port *OmadaSwitchPort, profile *OmadaLanProfile, native string, tags []string) (string, error) {
	ordered := slices.Clone(tags)
	slices.Sort(ordered)
	raw, err := json.Marshal(struct {
		Site    string
		Port    *OmadaSwitchPort
		Profile *OmadaLanProfile
		Native  string
		Tagged  []string
	}{siteID, port, profile, native, ordered})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
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
		LinkSpeed:          p.LinkSpeed,
		Duplex:             p.Duplex,
		LinkSpeedSource:    omadabackend.LinkSpeedConfigured,
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
