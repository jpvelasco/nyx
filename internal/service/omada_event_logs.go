package service

import (
	"context"

	omada "github.com/jpvelasco/nyx/internal/backends/omada"
)

type OmadaEventLogQuery = omada.EventLogQuery
type OmadaEventLogPage = omada.EventLogPage

// ListEventLogs returns a page of site event history.
func (s *OmadaService) ListEventLogs(ctx context.Context, opts OmadaOptions, query OmadaEventLogQuery) (OmadaEventLogPage, error) {
	return withSession(s, ctx, opts, func(client *omada.Client, siteID string) (OmadaEventLogPage, error) {
		return client.GetEventLogs(ctx, siteID, query)
	})
}
