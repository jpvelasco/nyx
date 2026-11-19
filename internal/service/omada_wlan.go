package service

import (
	"context"

	"github.com/jpvelasco/nyx/internal/backends/omada"
)

func (s *OmadaService) ListWLANOptimizationHistory(ctx context.Context, opts OmadaOptions) ([]omada.WLANOptimizationRun, error) {
	return withSession(s, ctx, opts, func(c *omada.Client, siteID string) ([]omada.WLANOptimizationRun, error) {
		return c.ListWLANOptimizationHistory(ctx, siteID)
	})
}

func (s *OmadaService) GetWLANOptimizationHistory(ctx context.Context, opts OmadaOptions, historyID string) (omada.WLANOptimizationDetail, error) {
	return withSession(s, ctx, opts, func(c *omada.Client, siteID string) (omada.WLANOptimizationDetail, error) {
		return c.GetWLANOptimizationHistory(ctx, siteID, historyID)
	})
}
