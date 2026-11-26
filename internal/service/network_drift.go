package service

import (
	"context"
	"errors"
	"time"

	"github.com/jpvelasco/nyx/internal/snapshot"
)

const MapCaptureCommand = "capture-map"
const MapCaptureTool = "network_map_capture"
const MapDriftCommand = "map-drift"
const MapDriftTool = "network_map_drift"

// CaptureMap stores private native identities locally. The response only carries the capture time.
func (s *TopologyService) CaptureMap(ctx context.Context, opts NetworkMapOptions, name, audit string, replace bool) (map[string]time.Time, error) {
	c, err := s.currentMapCapture(ctx, opts, audit)
	if err != nil {
		return nil, err
	}
	if err := snapshot.SaveNetworkMapCapture(name, c, replace); err != nil {
		return nil, err
	}
	return map[string]time.Time{"captured_at": c.At}, nil
}
func (s *TopologyService) currentMapCapture(ctx context.Context, opts NetworkMapOptions, audit string) (snapshot.NetworkMapCapture, error) {
	c := snapshot.NetworkMapCapture{Version: 1}
	if audit != "" {
		a, err := snapshot.ReadNamedAudit(audit)
		if err != nil {
			return c, err
		}
		c.AddServicePolicies(a)
	}
	opts.Detail = true
	m, err := s.Map(ctx, opts)
	if err != nil {
		return c, err
	}
	c.Map = m
	c.At = time.Now().UTC()
	return c, nil
}

// MapDrift compares two captures, or a saved baseline against a fresh read.
func (s *TopologyService) MapDrift(ctx context.Context, opts NetworkMapOptions, before, after, audit, age string) (snapshot.NetworkDrift, error) {
	if age == "" {
		age = "24h"
	}
	maxAge, err := time.ParseDuration(age)
	if err != nil || maxAge <= 0 {
		return snapshot.NetworkDrift{}, errors.New("max age must be a positive duration")
	}
	a, err := snapshot.LoadNetworkMapCapture(before)
	if err != nil {
		return snapshot.NetworkDrift{}, err
	}
	var b snapshot.NetworkMapCapture
	if after != "" {
		if audit != "" || len(opts.Connections) > 0 {
			return snapshot.NetworkDrift{}, errors.New("a second saved map already contains its source and policy selections")
		}
		b, err = snapshot.LoadNetworkMapCapture(after)
	} else {
		if len(opts.Connections) == 0 {
			for _, src := range a.Map.Sources {
				opts.Connections = append(opts.Connections, src.Provider+"/"+src.Profile)
			}
		}
		b, err = s.currentMapCapture(ctx, opts, audit)
	}
	if err != nil {
		return snapshot.NetworkDrift{}, err
	}
	if b.At.Before(a.At) {
		return snapshot.NetworkDrift{}, errors.New("the second map predates the baseline")
	}
	return snapshot.CompareNetworkMaps(a, b, maxAge), nil
}
