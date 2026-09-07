package omada

import (
	"context"
	"fmt"
	"strings"
)

// WLANGroup is a site WLAN group (Open API 6.2.14 sites/{id}/wlan-groups).
type WLANGroup struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name"`
}

// SSID is a site SSID (Open API 6.2.14 sites/{id}/ssids).
type SSID struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name"`
	SSID        string `json:"ssid"`
	Enabled     bool   `json:"enable"`
	WLANGroupID string `json:"wlanGroupId,omitempty"`
	VLANID      int    `json:"vlanId,omitempty"`
	Security    string `json:"security,omitempty"`
	Band        string `json:"band,omitempty"`
}

// SSIDWrite is the create/update payload.
type SSIDWrite struct {
	Name        string `json:"name"`
	SSID        string `json:"ssid"`
	Enabled     bool   `json:"enable"`
	WLANGroupID string `json:"wlanGroupId,omitempty"`
	VLANID      int    `json:"vlanId,omitempty"`
	Security    string `json:"security,omitempty"`
	Band        string `json:"band,omitempty"`
}

// GetWLANGroups lists site WLAN groups.
func (c *Client) GetWLANGroups(ctx context.Context, siteID string) ([]WLANGroup, error) {
	rows, _, err := fetchPaged[WLANGroup](ctx, c, fmt.Sprintf("sites/%s/wlan-groups", siteID), defaultPageSize)
	if err != nil {
		return nil, fmt.Errorf("fetching WLAN groups: %w", err)
	}
	if rows == nil {
		rows = []WLANGroup{}
	}
	return rows, nil
}

// GetSSIDs lists site SSIDs.
func (c *Client) GetSSIDs(ctx context.Context, siteID string) ([]SSID, error) {
	rows, _, err := fetchPaged[SSID](ctx, c, fmt.Sprintf("sites/%s/ssids", siteID), defaultPageSize)
	if err != nil {
		return nil, fmt.Errorf("fetching SSIDs: %w", err)
	}
	if rows == nil {
		rows = []SSID{}
	}
	return rows, nil
}

// CreateSSID POSTs a new SSID and returns its id.
func (c *Client) CreateSSID(ctx context.Context, siteID string, w SSIDWrite) (string, error) {
	var res struct {
		ID string `json:"id"`
	}
	if err := c.post(ctx, fmt.Sprintf("sites/%s/ssids", siteID), w, &res); err != nil {
		return "", fmt.Errorf("creating SSID %q: %w", w.Name, err)
	}
	if res.ID == "" {
		return "", fmt.Errorf("creating SSID %q: controller returned no id", w.Name)
	}
	return res.ID, nil
}

// UpdateSSID PUTs the writable SSID payload.
func (c *Client) UpdateSSID(ctx context.Context, siteID, id string, w SSIDWrite) error {
	if err := c.put(ctx, fmt.Sprintf("sites/%s/ssids/%s", siteID, id), w, nil); err != nil {
		return fmt.Errorf("updating SSID %q: %w", id, err)
	}
	return nil
}

// DeleteSSID deletes a site SSID.
func (c *Client) DeleteSSID(ctx context.Context, siteID, id string) error {
	if err := c.delete(ctx, fmt.Sprintf("sites/%s/ssids/%s", siteID, id)); err != nil {
		return fmt.Errorf("deleting SSID %q: %w", id, err)
	}
	return nil
}

// FindSSID matches by id, name, or broadcast SSID (case-insensitive).
func FindSSID(rows []SSID, name string) (SSID, bool) {
	for _, s := range rows {
		if strings.EqualFold(s.ID, name) || strings.EqualFold(s.Name, name) || strings.EqualFold(s.SSID, name) {
			return s, true
		}
	}
	return SSID{}, false
}

// SSIDMatchesWrite reports whether an existing SSID already has the
// requested broadcast name, enable, VLAN, and security.
func SSIDMatchesWrite(s SSID, w SSIDWrite) bool {
	return strings.EqualFold(s.SSID, w.SSID) &&
		s.Enabled == w.Enabled &&
		s.VLANID == w.VLANID &&
		strings.EqualFold(s.Security, w.Security) &&
		(w.WLANGroupID == "" || s.WLANGroupID == w.WLANGroupID)
}
