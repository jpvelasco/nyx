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
