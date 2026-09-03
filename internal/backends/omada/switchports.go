package omada

import (
	"context"
	"fmt"
	"sort"
)

// Switch-port observation and LAN-profile primitives over the per-scope
// Open API collections. The ports-overview row carries the port's current
// profileId/profileName but not the per-VLAN tag/untagged sets — those live
// in the site's lan-profiles collection, which the profileId references.
// The setProfileForGivenPort PUT is the only port-write surface nyx uses;
// the profile-override endpoint is deliberately not wired.

// SwitchPort is one row of the switches/ports/overview collection. Nested
// standardPort/portStatus/lagSetting blocks are not modeled — the flat
// fields below are what port-profile planning consumes. tagName/tagIds are
// port labels (user tags), NOT VLAN membership.
type SwitchPort struct {
	Port               int    `json:"port"`
	PortName           string `json:"portName"`
	SwitchMAC          string `json:"switchMac"`
	SwitchName         string `json:"switchName"`
	ConnectedStatus    int    `json:"connectedStatus"` // 0 Connected, 1 Disconnected, 2 Disable
	Disable            bool   `json:"disable"`
	Type               int    `json:"type"` // 1 Copper, 2 Combo, 3 SFP
	Operation          string `json:"operation"`
	LinkSpeed          int    `json:"linkSpeed"`
	Duplex             int    `json:"duplex"`
	NetworkMode        int    `json:"networkMode"` // 0 Trunk, 1 Access
	NativeNetworkID    string `json:"nativeNetworkId"`
	NativeBridgeVLAN   int    `json:"nativeBridgeVlan"`
	NetworkTagsSetting int    `json:"networkTagsSetting"` // 0 Allow All, 1 Block All, 2 Custom
	ProfileID          string `json:"profileId"`
	ProfileName        string `json:"profileName"`
	ProfileOverride    bool   `json:"profileOverrideEnable"`
	ProfileType        int    `json:"profileType"`
}

// UplinkInfo is one device uplink row: which managed device (and port) the
// queried MAC is cabled into.
type UplinkInfo struct {
	MAC              string `json:"mac"`
	UplinkDeviceMAC  string `json:"uplinkDeviceMac"`
	UplinkDeviceName string `json:"uplinkDeviceName"`
	UplinkDevicePort string `json:"uplinkDevicePort"` // controller sends the port as a string, e.g. "8"
	LinkSpeed        int    `json:"linkSpeed"`        // 0 Auto, 1 10M, 2 100M, 3 1000M, 4 2500M, 5 10G
	Duplex           int    `json:"duplex"`           // 0 Auto, 1 Half, 2 Full
}

// LanProfile is a site-wide LAN profile (the VLAN membership set bound to
// ports via profileId). The read collection omits read-only bookkeeping;
// the create payload carries only the controller's required fields plus
// the VLAN membership sets.
type LanProfile struct {
	ID                   string   `json:"id,omitempty"`
	Flag                 int      `json:"flag,omitempty"` // 0 default, 1 native, 2 custom
	Name                 string   `json:"name"`
	PoE                  int      `json:"poe"` // 0 on, 1 off, 2 do not modify
	NativeNetworkID      string   `json:"nativeNetworkId"`
	TagNetworkIDs        []string `json:"tagNetworkIds"`
	UntagNetworkIDs      []string `json:"untagNetworkIds"`
	VoiceNetworkID       string   `json:"voiceNetworkId,omitempty"`
	Dot1x                int      `json:"dot1x"` // 0 force unauthorized, 1 force authorized, 2 auto
	PortIsolationEnable  bool     `json:"portIsolationEnable"`
	LLDPMEDEnable        bool     `json:"lldpMedEnable"`
	BandWidthCtrlType    int      `json:"bandWidthCtrlType"` // 0 off, 1 rate limit, 2 storming
	SpanningTreeEnable   bool     `json:"spanningTreeEnable"`
	LoopbackDetectEnable bool     `json:"loopbackDetectEnable"`
}

// PoEDoNotModify is the create-payload PoE sentinel that leaves a port's
// existing PoE state untouched.
const PoEDoNotModify = 2

// Dot1xAuto is the create-payload 802.1x sentinel (controller default).
const Dot1xAuto = 2

// BandWidthCtrlOff is the create-payload bandwidth-control sentinel.
const BandWidthCtrlOff = 0

// GetUplinkInfo posts the device MAC list to the uplink-info endpoint. The
// result is a direct (unpaged) array, one row per queried MAC; unknown MACs
// yield no row.
func (c *Client) GetUplinkInfo(ctx context.Context, siteID string, macs []string) ([]UplinkInfo, error) {
	var rows []UplinkInfo
	if err := c.post(ctx, fmt.Sprintf("sites/%s/devices/uplink-info", siteID), map[string][]string{"deviceMacs": macs}, &rows); err != nil {
		return nil, fmt.Errorf("fetching uplink info: %w", err)
	}
	return rows, nil
}

// GetSwitchPortsOverview returns every port row of the site, joined across
// pages. An empty site yields an empty slice, not nil.
func (c *Client) GetSwitchPortsOverview(ctx context.Context, siteID string) ([]SwitchPort, error) {
	rows, _, err := fetchPaged[SwitchPort](ctx, c, fmt.Sprintf("sites/%s/switches/ports/overview", siteID), defaultPageSize)
	if err != nil {
		return nil, fmt.Errorf("fetching switch ports overview: %w", err)
	}
	if rows == nil {
		rows = []SwitchPort{}
	}
	return rows, nil
}

// GetLanProfiles returns every LAN profile of the site. An empty site yields
// an empty slice, not nil.
func (c *Client) GetLanProfiles(ctx context.Context, siteID string) ([]LanProfile, error) {
	rows, _, err := fetchPaged[LanProfile](ctx, c, fmt.Sprintf("sites/%s/lan-profiles", siteID), defaultPageSize)
	if err != nil {
		return nil, fmt.Errorf("fetching LAN profiles: %w", err)
	}
	if rows == nil {
		rows = []LanProfile{}
	}
	return rows, nil
}

// CreateLanProfile POSTs a new site-wide LAN profile and returns the new
// profile id. The controller's required-field set is name, poe,
// nativeNetworkId, dot1x, portIsolationEnable, lldpMedEnable,
// bandWidthCtrlType, spanningTreeEnable, and loopbackDetectEnable — the
// caller must send them explicitly (a partial profile is rejected with
// -1001).
func (c *Client) CreateLanProfile(ctx context.Context, siteID string, p LanProfile) (string, error) {
	var res struct {
		ID string `json:"id"`
	}
	if err := c.post(ctx, fmt.Sprintf("sites/%s/lan-profiles", siteID), p, &res); err != nil {
		return "", fmt.Errorf("creating LAN profile %q: %w", p.Name, err)
	}
	if res.ID == "" {
		return "", fmt.Errorf("creating LAN profile %q: controller returned no profile id", p.Name)
	}
	return res.ID, nil
}

// SetPortProfile binds a LAN profile to one port. The response carries no
// payload — the caller re-reads the port to confirm.
func (c *Client) SetPortProfile(ctx context.Context, siteID, switchMAC string, port int, profileID string) error {
	if err := c.put(ctx, fmt.Sprintf("sites/%s/switches/%s/ports/%d/profile", siteID, switchMAC, port),
		map[string]string{"profileId": profileID}, nil); err != nil {
		return fmt.Errorf("setting LAN profile on port %d: %w", port, err)
	}
	return nil
}

// ProfileMatchesMembership reports whether one profile's (native, tagged,
// untagged) network-ID set equals the desired one.
func ProfileMatchesMembership(p LanProfile, nativeID string, tagIDs, untagIDs []string) bool {
	return p.NativeNetworkID == nativeID &&
		sortedIDEqual(p.TagNetworkIDs, tagIDs) &&
		sortedIDEqual(p.UntagNetworkIDs, untagIDs)
}

// FindLanProfile returns the first profile whose (native, tagged, untagged)
// network-ID set equals the desired one. Matching is on the ID sets only —
// two profiles with the same membership are interchangeable for a port, and
// reusing one avoids orphaning a new profile on every re-apply.
func FindLanProfile(profiles []LanProfile, nativeID string, tagIDs, untagIDs []string) *LanProfile {
	for i := range profiles {
		if ProfileMatchesMembership(profiles[i], nativeID, tagIDs, untagIDs) {
			return &profiles[i]
		}
	}
	return nil
}

// sortedIDEqual reports whether two network-ID sets are equal as sets
// (order-insensitive, no duplicates expected from the controller).
func sortedIDEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ca, cb := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(ca)
	sort.Strings(cb)
	for i := range ca {
		if ca[i] != cb[i] {
			return false
		}
	}
	return true
}
