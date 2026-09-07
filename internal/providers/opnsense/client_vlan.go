package opnsense

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// VLAN is one row from GET /api/interfaces/vlan_settings/search_item.
type VLAN struct {
	UUID        string `json:"uuid"`
	Parent      string `json:"parent"`
	Tag         int    `json:"tag"`
	Description string `json:"description,omitempty"`
	Device      string `json:"device,omitempty"`
}

// VLANWrite is the create/update payload for a VLAN device.
type VLANWrite struct {
	Parent      string
	Tag         int
	Description string
}

const (
	vlanSearchPath        = "/interfaces/vlan_settings/search_item"
	vlanAddPath           = "/interfaces/vlan_settings/add_item"
	vlanSetPath           = "/interfaces/vlan_settings/set_item/%s"
	vlanDelPath           = "/interfaces/vlan_settings/del_item/%s"
	vlanReconfigurePath   = "/interfaces/vlan_settings/reconfigure"
	bridgeAddPath         = "/interfaces/bridge_settings/add_item"
	bridgeSetPath         = "/interfaces/bridge_settings/set_item/%s"
	bridgeReconfigurePath = "/interfaces/bridge_settings/reconfigure"
)

// AssignIPGapWarning is the open upstream limitation: creating a VLAN
// device or editing bridge members does not assign the device to optN
// or set addressing. The GUI still owns that step.
const AssignIPGapWarning = "creating the VLAN or bridge device does not assign it to an opt " +
	"or set addressing; finish that in the GUI, then continue with DHCP and filter writes"

// GetVLANs returns configured VLAN devices (GET search_item).
func (c *Client) GetVLANs(ctx context.Context) ([]VLAN, error) {
	var raw []json.RawMessage
	if _, err := fetchPagedList(ctx, c, vlanSearchPath, listPageSize, &raw); err != nil {
		return nil, remapPagedDecode(err, "decoding VLAN settings response")
	}
	out := make([]VLAN, 0, len(raw))
	for _, row := range raw {
		var rec struct {
			UUID        string `json:"uuid"`
			If          string `json:"if"`
			Tag         string `json:"tag"`
			Descr       string `json:"descr"`
			Description string `json:"description"`
			Vlanif      string `json:"vlanif"`
		}
		if err := json.Unmarshal(row, &rec); err != nil || rec.UUID == "" {
			continue
		}
		tag, _ := strconv.Atoi(rec.Tag)
		out = append(out, VLAN{
			UUID:        rec.UUID,
			Parent:      rec.If,
			Tag:         tag,
			Description: firstNonEmpty(rec.Description, rec.Descr),
			Device:      rec.Vlanif,
		})
	}
	return out, nil
}

func vlanWire(w VLANWrite) ([]byte, error) {
	item := map[string]interface{}{
		"if":  w.Parent,
		"tag": strconv.Itoa(w.Tag),
	}
	if w.Description != "" {
		item["descr"] = w.Description
	}
	return json.Marshal(map[string]interface{}{"vlan": item})
}

func bridgeWire(members []string, descr string) ([]byte, error) {
	item := map[string]interface{}{
		"members": strings.Join(members, ","),
	}
	if descr != "" {
		item["descr"] = descr
	}
	return json.Marshal(map[string]interface{}{"bridge": item})
}

// CreateVLAN POSTs add_item and returns the new uuid.
func (c *Client) CreateVLAN(ctx context.Context, w VLANWrite) (string, error) {
	body, err := vlanWire(w)
	if err != nil {
		return "", err
	}
	return c.natAdd(ctx, vlanAddPath, body)
}

// SetVLAN POSTs set_item/<uuid>.
func (c *Client) SetVLAN(ctx context.Context, uuid string, w VLANWrite) error {
	body, err := vlanWire(w)
	if err != nil {
		return err
	}
	return c.natSet(ctx, fmt.Sprintf(vlanSetPath, uuid), body)
}

// DeleteVLAN POSTs del_item/<uuid>.
func (c *Client) DeleteVLAN(ctx context.Context, uuid string) error {
	return c.natSet(ctx, fmt.Sprintf(vlanDelPath, uuid), []byte(`{}`))
}

// ReconfigureVLANs activates staged VLAN device changes.
func (c *Client) ReconfigureVLANs(ctx context.Context) error {
	return c.postOK(ctx, vlanReconfigurePath)
}

// SetBridgeMembers POSTs set_item/<uuid> with the member list.
func (c *Client) SetBridgeMembers(ctx context.Context, uuid string, members []string, descr string) error {
	body, err := bridgeWire(members, descr)
	if err != nil {
		return err
	}
	return c.natSet(ctx, fmt.Sprintf(bridgeSetPath, uuid), body)
}

// ReconfigureBridges activates staged bridge member changes.
func (c *Client) ReconfigureBridges(ctx context.Context) error {
	return c.postOK(ctx, bridgeReconfigurePath)
}

func (c *Client) postOK(ctx context.Context, path string) error {
	resp, err := c.do(ctx, http.MethodPost, path, []byte(`{}`))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var res struct {
		Status string `json:"status"`
		Result string `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return fmt.Errorf("decoding reconfigure response: %w", err)
	}
	if res.Status != "" && res.Status != "ok" {
		return fmt.Errorf("reconfigure returned status %q", res.Status)
	}
	if res.Result != "" && res.Result != "ok" && res.Result != "saved" {
		return fmt.Errorf("reconfigure returned %q", res.Result)
	}
	return nil
}

// FindVLAN matches by uuid or parent+tag.
func FindVLAN(rows []VLAN, uuid, parent string, tag int) (VLAN, bool) {
	for _, v := range rows {
		if uuid != "" && strings.EqualFold(v.UUID, uuid) {
			return v, true
		}
		if parent != "" && tag > 0 && strings.EqualFold(v.Parent, parent) && v.Tag == tag {
			return v, true
		}
	}
	return VLAN{}, false
}

// VLANMatchesWrite reports whether an existing VLAN already has the
// requested parent, tag, and description.
func VLANMatchesWrite(v VLAN, w VLANWrite) bool {
	if !strings.EqualFold(v.Parent, w.Parent) || v.Tag != w.Tag {
		return false
	}
	if w.Description != "" && !strings.EqualFold(v.Description, w.Description) {
		return false
	}
	return true
}

// BridgeMembersMatch reports whether the bridge already has the requested
// member set (order-insensitive).
func BridgeMembersMatch(have, want []string) bool {
	if len(have) != len(want) {
		return false
	}
	seen := map[string]int{}
	for _, m := range have {
		seen[strings.ToLower(strings.TrimSpace(m))]++
	}
	for _, m := range want {
		k := strings.ToLower(strings.TrimSpace(m))
		if seen[k] == 0 {
			return false
		}
		seen[k]--
	}
	return true
}
