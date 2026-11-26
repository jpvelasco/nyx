package omada

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
)

// APChannels reports the observed channels and the controller's candidate list.
type APChannels struct {
	Name              string            `json:"name"`
	MAC               string            `json:"mac"`
	CurrentChannels   map[string]string `json:"current_channels"`
	AvailableChannels json.RawMessage   `json:"available_channels"`
}

// GetAPChannels inventories managed APs using the two supported per-AP reads.
func (c *Client) GetAPChannels(ctx context.Context, siteID string) ([]APChannels, error) {
	rows, _, err := c.APChannelsPage(ctx, siteID, 0, 0)
	return rows, err
}

// APChannelsPage fetches per-device details only inside the requested window. Zero limit requests all rows for the CLI.
func (c *Client) APChannelsPage(ctx context.Context, siteID string, offset, limit int) ([]APChannels, int, error) {
	devices, err := c.GetDevices(ctx, siteID)
	if err != nil {
		return nil, 0, err
	}
	aps := slices.DeleteFunc(SortedDevices(devices), func(d Device) bool { return !d.IsAP() })
	total := len(aps)
	start := min(max(offset, 0), total)
	if limit > 0 {
		aps = aps[:start+min(limit, total-start)]
	}
	rows := make([]APChannels, 0, len(aps)-start)
	for _, device := range aps[start:] {
		row, err := c.getAPChannels(ctx, siteID, device)
		if err != nil {
			return nil, total, err
		}
		rows = append(rows, row)
	}
	return rows, total, nil
}

func (c *Client) getAPChannels(ctx context.Context, siteID string, device Device) (APChannels, error) {
	row := APChannels{Name: device.Name, MAC: device.MAC, CurrentChannels: make(map[string]string)}
	path := fmt.Sprintf("sites/%s/aps/%s", url.PathEscape(siteID), url.PathEscape(dashMAC(device.MAC)))
	var radios map[string]json.RawMessage
	if err := c.get(ctx, path+"/radios", &radios); err != nil {
		return row, fmt.Errorf("getting AP radios for %s: %w", device.MAC, err)
	}
	for band, raw := range radios {
		// Other top-level radio statistics can be scalar values.
		var radio struct {
			ActualChannel string `json:"actualChannel"`
		}
		if json.Unmarshal(raw, &radio) == nil && radio.ActualChannel != "" {
			row.CurrentChannels[band] = radio.ActualChannel
		}
	}
	if err := c.get(ctx, path+"/available-channel", &row.AvailableChannels); err != nil {
		return row, fmt.Errorf("getting available channels for %s: %w", device.MAC, err)
	}
	return row, nil
}
