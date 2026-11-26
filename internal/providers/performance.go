package providers

import (
	"context"
	"github.com/jpvelasco/nyx/internal/topology"
)

const PerformanceCapability = "path_performance"

type PerformanceObserver interface {
	ObservePerformance(context.Context, ImportOptions, topology.PerformanceTarget) (topology.PassiveSample, error)
}
