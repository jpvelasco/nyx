package opnsense

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jpvelasco/nyx/internal/textsafe"
)

// RouterAdvertisement is one configured RADVD interface. Missing fields remain
// unknown. A successful empty search reports no configured entries.
type RouterAdvertisement struct {
	Interface string `json:"interface"`
	State     string `json:"state"`
	Mode      string `json:"mode,omitempty"`
}

// GetRouterAdvertisements reads the RADVD searchEntry action from the stable model.
func (c *Client) GetRouterAdvertisements(ctx context.Context) ([]RouterAdvertisement, error) {
	var rows []json.RawMessage
	total, err := fetchPagedList(ctx, c, "/radvd/settings/search_entry", listPageSize, &rows)
	if err != nil {
		return nil, err
	}
	if rows == nil || (total > 0 && total != len(rows)) {
		return nil, fmt.Errorf("incomplete router advertisement collection")
	}
	out := make([]RouterAdvertisement, 0, len(rows))
	for _, data := range rows {
		var row struct {
			Interface string          `json:"interface"`
			Enabled   json.RawMessage `json:"enabled"`
			Mode      string          `json:"mode"`
		}
		if err := json.Unmarshal(data, &row); err != nil || row.Interface == "" {
			return nil, fmt.Errorf("invalid router advertisement entry")
		}
		out = append(out, RouterAdvertisement{Interface: textsafe.Printable(row.Interface), State: configToggle(row.Enabled), Mode: textsafe.Printable(strings.TrimSpace(row.Mode))})
	}
	return out, nil
}
