package service

import (
	"context"

	"github.com/jpvelasco/nyx/internal/backends/omada"
)

// OmadaAttackDefense records the controller observations and runtime boundary.
type OmadaAttackDefense struct {
	Settings       omada.AttackDefenseSettings `json:"settings"`
	ClientBlocked  *bool                       `json:"controller_client_blocked,omitempty"`
	GatewayRuntime string                      `json:"gateway_runtime"`
	Guidance       string                      `json:"guidance"`
}

func (s *OmadaService) AttackDefense(ctx context.Context, opts OmadaOptions, mac string) (OmadaAttackDefense, error) {
	return withSession(s, ctx, opts, func(c *omada.Client, site string) (OmadaAttackDefense, error) {
		settings, err := c.GetAttackDefenseSettings(ctx, site)
		if err != nil {
			return OmadaAttackDefense{}, err
		}
		report := OmadaAttackDefense{
			Settings:       settings,
			GatewayRuntime: "device_side_unobservable",
			Guidance:       "Inspect the enforcing gateway for runtime attack-defense blocks. The site settings and controller client block flag cannot establish the gateway's runtime block state.",
		}
		if mac != "" {
			report.ClientBlocked, err = c.ClientBlockStatus(ctx, site, mac)
		}
		return report, err
	})
}

func (s *OmadaService) UnblockClient(ctx context.Context, opts OmadaOptions, mac string) error {
	_, err := withSession(s, ctx, opts, func(c *omada.Client, site string) (struct{}, error) {
		return struct{}{}, c.UnblockClient(ctx, site, mac)
	})
	return err
}
