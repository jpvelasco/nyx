package service

import (
	"context"

	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
)

// ListAPChannels returns current and candidate channels for the site's APs.
func (s *OmadaService) ListAPChannels(ctx context.Context, opts OmadaOptions) ([]omadabackend.APChannels, error) {
	client, site, err := s.session(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer client.Logout(ctx) //nolint:errcheck
	return client.GetAPChannels(ctx, site.EffectiveID())
}
