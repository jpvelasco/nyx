package service

import (
	"context"

	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
)

// ReadSiteConfig reads the site's network, switch ACL, and WLAN configuration.
func (s *OmadaService) ReadSiteConfig(ctx context.Context, opts OmadaOptions) (omadabackend.SiteConfigState, error) {
	return withSession(s, ctx, opts, func(client *omadabackend.Client, siteID string) (omadabackend.SiteConfigState, error) {
		return client.GetSiteConfig(ctx, siteID)
	})
}
