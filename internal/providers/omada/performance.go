package omadaprovider

import (
	"context"
	backend "github.com/jpvelasco/nyx/internal/backends/omada"
	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/topology"
	"time"
)

func (*OmadaProvider) ObservePerformance(ctx context.Context, opts providers.ImportOptions, target topology.PerformanceTarget) (topology.PassiveSample, error) {
	s := topology.PassiveSample{Status: "unsupported"}
	c, site, err := openACLSite(ctx, opts)
	if err != nil {
		return s, err
	}
	defer c.Logout(ctx)
	id := site.EffectiveID()
	switch target.Kind {
	case "switch_port":
		rows, err := c.PortCounters(ctx, id)
		if err != nil {
			return s, err
		}
		for _, r := range rows {
			if r.Port != target.Port || backend.NormalizeMAC(r.SwitchMAC) != backend.NormalizeMAC(target.SwitchMAC) {
				continue
			}
			if s.Status == "available" {
				return topology.PassiveSample{Status: "ambiguous", At: time.Now().UTC()}, nil
			}
			s.Status = "available"
			s.ConfiguredSpeed = r.ConfiguredSpeed
			s.RxBytes = r.RxBytes
			s.TxBytes = r.TxBytes
			s.RxErrors = r.RxErrors
			s.TxErrors = r.TxErrors
			s.RxRate = r.Status.RxRate
			s.TxRate = r.Status.TxRate
			if r.Status.Link != nil && (*r.Status.Link == 0 || *r.Status.Link == 1) {
				up := *r.Status.Link == 1
				s.LinkUp = &up
				if up && r.Status.Speed != nil {
					if speed, ok := map[int]int{1: 10, 2: 100, 3: 1000, 4: 10000}[*r.Status.Speed]; ok {
						s.ObservedMbps = &speed
					}
				}
			}
		}
	case "channel":
		rows, err := c.ChannelUsage(ctx, id)
		if err != nil {
			return s, err
		}
		for _, r := range rows[target.Band+" channel stat"] {
			if r.Channel == target.Channel && r.Utilization != nil && *r.Utilization >= 0 && *r.Utilization <= 100 {
				s.Status = "available"
				s.Utilization = r.Utilization
				break
			}
		}
		if target.APMAC != "" {
			percent, readErr := c.RadioInterference(ctx, id, target.APMAC, target.Band, target.Channel)
			if readErr == nil && percent != nil {
				s.Interference = percent
				s.Status = "available"
			}
		}
	}
	s.At = time.Now().UTC()
	return s, nil
}
