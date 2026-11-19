package service

import (
	"context"
	"io"

	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
)

// UpgradeDevice runs the explicitly authorized manual firmware workflow.
func (s *OmadaService) UpgradeDevice(ctx context.Context, opts OmadaOptions, mac, expected string, image io.Reader, confirmed bool) (omadabackend.DeviceUpgrade, error) {
	return withSession(s, ctx, opts, func(client *omadabackend.Client, siteID string) (omadabackend.DeviceUpgrade, error) {
		return client.UpgradeDevice(ctx, siteID, mac, expected, image, confirmed)
	})
}
