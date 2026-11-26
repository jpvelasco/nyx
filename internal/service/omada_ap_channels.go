package service

import (
	"context"

	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
)

// ListAPChannels returns current and candidate channels for the site's APs.
func (s *OmadaService) ListAPChannels(ctx context.Context, opts OmadaOptions) ([]omadabackend.APChannels, error) {
	return withSession(s, ctx, opts, func(client *omadabackend.Client, siteID string) ([]omadabackend.APChannels, error) {
		return client.GetAPChannels(ctx, siteID)
	})
}

// APChannelPage returns the requested window and total number of site APs.
type APChannelPage struct {
	Rows   []omadabackend.APChannels `json:"rows"`
	Total  int                       `json:"total"`
	Offset int                       `json:"offset"`
}

func (s *OmadaService) APChannelsPage(ctx context.Context, opts OmadaOptions, offset, limit int, private bool) (APChannelPage, error) {
	return withSession(s, ctx, opts, func(c *omadabackend.Client, siteID string) (APChannelPage, error) {
		rows, total, err := c.APChannelsPage(ctx, siteID, offset, limit)
		if !private {
			for i := range rows {
				rows[i].Name = ""
				rows[i].MAC = ""
			}
		}
		return APChannelPage{Rows: rows, Total: total, Offset: offset}, err
	})
}
