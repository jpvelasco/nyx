package service

import (
	"context"
	"errors"
	"time"

	"github.com/jpvelasco/nyx/internal/backends/omada"
)

func (s *OmadaService) PendingDevices(ctx context.Context, opts OmadaOptions, page, size int, private bool) (omada.PendingDevices, error) {
	if opts.Site == "" {
		return omada.PendingDevices{}, errors.New("select an explicit Omada site")
	}
	return withSession(s, ctx, opts, func(c *omada.Client, siteID string) (omada.PendingDevices, error) {
		out, err := c.PendingDevices(ctx, siteID, page, size, "")
		if !private {
			for i := range out.Devices {
				out.Devices[i].MAC = ""
			}
		}
		return out, err
	})
}
func (s *OmadaService) ObserveAdoption(ctx context.Context, opts OmadaOptions, mac string, wait time.Duration) (omada.AdoptionObservation, error) {
	if opts.Site == "" {
		return omada.AdoptionObservation{}, errors.New("select an explicit Omada site")
	}
	return withSession(s, ctx, opts, func(c *omada.Client, siteID string) (omada.AdoptionObservation, error) {
		return c.ObserveAdoption(ctx, siteID, mac, wait)
	})
}
