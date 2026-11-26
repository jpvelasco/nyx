package providers

import (
	"context"

	"github.com/jpvelasco/nyx/internal/topology"
)

const NetworkMapCapability = "network_map"

// NetworkObserver returns typed observations read from one selected connection.
type NetworkObserver interface {
	ObserveNetwork(context.Context, ImportOptions) (topology.ObservationSet, error)
}
