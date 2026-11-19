package omada

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
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
	devices, err := c.GetDevices(ctx, siteID)
	if err != nil {
		return nil, err
	}
	rows := make([]APChannels, 0)
	for _, device := range SortedDevices(devices) {
		if !device.IsAP() {
			continue
		}
		row, err := c.getAPChannels(ctx, siteID, device)
		if err != nil {
			return nil, err
		}
		rows = append(rows, row)
	}
	return rows, nil
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
