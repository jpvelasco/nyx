package omada

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

type PortCounters struct {
	SwitchMAC       string  `json:"switchMac"`
	Port            int     `json:"port"`
	ConfiguredSpeed *int    `json:"linkSpeed"`
	TxBytes         *uint64 `json:"txBytes"`
	RxBytes         *uint64 `json:"rxBytes"`
	TxErrors        *uint64 `json:"txErrors"`
	RxErrors        *uint64 `json:"rxErrors"`
	Status          struct {
		Link   *int    `json:"linkStatus"`
		Speed  *int    `json:"linkSpeed"`
		TxRate *uint64 `json:"txRate"`
		RxRate *uint64 `json:"rxRate"`
	} `json:"portStatus"`
}

func (c *Client) PortCounters(ctx context.Context, siteID string) ([]PortCounters, error) {
	rows, _, err := fetchPaged[PortCounters](ctx, c, fmt.Sprintf("sites/%s/switches/ports/counters", siteID), defaultPageSize)
	return rows, err
}

type ChannelUsage struct {
	Channel     int      `json:"channel"`
	Utilization *float64 `json:"channelUtilization"`
}

func (c *Client) ChannelUsage(ctx context.Context, siteID string) (map[string][]ChannelUsage, error) {
	var rows map[string][]ChannelUsage
	err := c.get(ctx, fmt.Sprintf("sites/%s/dashboard/channels", siteID), &rows)
	return rows, err
}

// RadioInterference reads the AP's current radio table and matches the actual
// channel before returning its interUtil percentage. Radios can change channels.
func (c *Client) RadioInterference(ctx context.Context, siteID, ap, band string, channel int) (*float64, error) {
	var rows map[string]json.RawMessage
	path := fmt.Sprintf("sites/%s/aps/%s/radios", url.PathEscape(siteID), url.PathEscape(dashMAC(ap)))
	if err := c.get(ctx, path, &rows); err != nil {
		return nil, err
	}
	var found *float64
	for k, raw := range rows {
		second5GHzRadio := band == "5g" && k == "wp5g2"
		if k != "wp"+band && !second5GHzRadio {
			continue
		}
		var r struct {
			Channel      string   `json:"actualChannel"`
			Interference *float64 `json:"interUtil"`
		}
		if json.Unmarshal(raw, &r) != nil {
			continue
		}
		first, _, _ := strings.Cut(r.Channel, "/")
		n, err := strconv.Atoi(strings.TrimSpace(first))
		if err != nil || n != channel || r.Interference == nil || *r.Interference < 0 || *r.Interference > 100 {
			continue
		}
		if found != nil {
			return nil, nil
		}
		found = r.Interference
	}
	return found, nil
}
