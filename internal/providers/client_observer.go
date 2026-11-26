package providers

import (
	"context"

	"github.com/jpvelasco/nyx/internal/topology"
)

const ClientLocationCapability = "client_location"

// ClientObserver collects passive evidence for exactly one selected client.
type ClientObserver interface {
	ObserveClient(context.Context, ImportOptions, string) ([]topology.ClientObservation, []string, error)
}
