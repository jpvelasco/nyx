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
	inputs, err := collectMapInputs(ctx, opts, "")
	if err != nil {
		return topology.NetworkMap{}, err
	}
	maps := make([]topology.MapInput, 0, len(inputs))
	for _, in := range inputs {
		maps = append(maps, in.MapInput)
	}
	return topology.BuildNetworkMap(maps, opts.Detail), nil
}

func collectMapInputs(ctx context.Context, opts NetworkMapOptions, clientMAC string) ([]topology.ClientMapInput, error) {
	path := storepath.StoreFile()
	selected, err := mapConnections(ctx, path, opts.Connections)
	if err != nil {
		return nil, err
	}
	inputs := make([]topology.ClientMapInput, 0, len(selected))
	for _, c := range selected {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		inputs = append(inputs, observeMapConnection(ctx, c, path, opts, clientMAC))
	}
	return inputs, ctx.Err()
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

func observeMapConnection(ctx context.Context, c credentials.Connection, path string, opts NetworkMapOptions, clientMAC string) topology.ClientMapInput {
	input := topology.ClientMapInput{MapInput: topology.MapInput{Provider: c.Provider, Profile: c.ProfileName()}}
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
	if clientMAC != "" {
		reader, ok := adapter.(providers.ClientObserver)
		if !ok || !slices.Contains(adapter.Capabilities(), providers.ClientLocationCapability) {
			input.Facts.Gaps = append(input.Facts.Gaps, "client evidence unsupported")
			return input
		}
		rows, gaps, err := reader.ObserveClient(ctx, connection, clientMAC)
		input.Evidence = rows
		input.Facts.Gaps = append(input.Facts.Gaps, gaps...)
		if err != nil {
			input.Facts.Gaps = append(input.Facts.Gaps, "client evidence "+readAccess(err))
		}
	}
	return input
}
