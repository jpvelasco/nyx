package service

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"os"
	"slices"
	"strings"

	"github.com/jpvelasco/nyx/internal/credentials"
	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/storepath"
	"github.com/jpvelasco/nyx/internal/topology"
)

const NetworkMapCommand = "map"
const NetworkMapTool = providers.NetworkMapCapability

// NetworkMapOptions selects configured provider profiles; an empty list maps all of them.
type NetworkMapOptions struct {
	Connections           []string
	Detail, SkipTLSVerify bool
	CACertPath            string
	Logger                *slog.Logger
}

// Map reads authenticated observations from configured adapters. Only a shared,
// operator-assigned logical site permits links between different connections.
func (*TopologyService) Map(ctx context.Context, opts NetworkMapOptions) (topology.NetworkMap, error) {
	path := storepath.StoreFile()
	selected, err := mapConnections(ctx, path, opts.Connections)
	if err != nil {
		return topology.NetworkMap{}, err
	}
	inputs := make([]topology.MapInput, 0, len(selected))
	for _, c := range selected {
		if err := ctx.Err(); err != nil {
			return topology.NetworkMap{}, err
		}
		inputs = append(inputs, observeMapConnection(ctx, c, path, opts))
	}
	if err := ctx.Err(); err != nil {
		return topology.NetworkMap{}, err
	}
	return topology.BuildNetworkMap(inputs, opts.Detail), nil
}

func mapConnections(ctx context.Context, path string, selectors []string) ([]credentials.Connection, error) {
	var connections []credentials.Connection
	if len(selectors) == 0 {
		reports, err := ProviderCapabilityReport(ctx, CapabilityOptions{}, path, os.Getenv)
		if err != nil {
			return nil, errors.New("unable to enumerate configured connections")
		}
		for _, r := range reports {
			for _, c := range r.Connections {
				connections = append(connections, c.Connection)
			}
		}
	} else {
		for _, selector := range selectors {
			name, profile, ok := strings.Cut(selector, "/")
			if name == "" || (ok && profile == "") {
				return nil, errors.New("use a provider or provider/profile for each connection")
			}
			if _, ok := providers.LookupAdapter(name); !ok {
				return nil, errors.New("connection selects an unregistered provider")
			}
			if profile == "" {
				profile = "default"
			}
			connections = append(connections, credentials.Connection{Provider: name, Profile: profile})
		}
	}
	if len(connections) == 0 {
		return nil, errors.New("network map needs at least one configured provider connection")
	}
	slices.SortFunc(connections, func(a, b credentials.Connection) int {
		return cmp.Or(strings.Compare(a.Provider, b.Provider), strings.Compare(a.Profile, b.Profile))
	})
	return slices.Compact(connections), nil
}

func observeMapConnection(ctx context.Context, c credentials.Connection, path string, opts NetworkMapOptions) topology.MapInput {
	input := topology.MapInput{Provider: c.Provider, Profile: c.ProfileName()}
	adapter, _ := providers.LookupAdapter(c.Provider)
	observer, ok := adapter.(providers.NetworkObserver)
	if !ok || !slices.Contains(adapter.Capabilities(), providers.NetworkMapCapability) {
		input.Facts.Gaps = []string{"unsupported"}
		return input
	}
	fields := credentials.Resolve(c, nil, os.Getenv, path, true)
	input.Site = fields["site"]
	input.LogicalSite = fields["logical_site"]
	if c.Require(fields) != nil || fields["host"] == "" {
		input.Facts.Gaps = []string{"missing_credentials"}
		return input
	}
	connection := providers.ConnectionOptions(c, fields)
	connection.SkipTLSVerify = opts.SkipTLSVerify
	connection.CACertPath = opts.CACertPath
	connection.Logger = opts.Logger
	facts, err := observer.ObserveNetwork(ctx, connection)
	if err != nil {
		facts.Gaps = append(facts.Gaps, readAccess(err))
	}
	input.Facts = facts
	return input
}
