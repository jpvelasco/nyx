package service

import (
	"context"
	"errors"
	"github.com/jpvelasco/nyx/internal/credentials"
	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/storepath"
	"github.com/jpvelasco/nyx/internal/topology"
	"strings"
	"sync"
	"time"
)

const PerformanceCommand = "performance"
const PerformanceTool = providers.PerformanceCapability

type PerformanceReport struct {
	Interval string                    `json:"requested_interval"`
	Start    time.Time                 `json:"started_at"`
	End      time.Time                 `json:"finished_at"`
	Hops     []topology.HopPerformance `json:"hops"`
}

func samplePath(ctx context.Context, opts NetworkMapOptions, path []topology.PerformanceTarget) []topology.PassiveSample {
	samples := make([]topology.PassiveSample, len(path))
	var wg sync.WaitGroup
	for i, t := range path {
		wg.Go(func() {
			sample := topology.PassiveSample{Status: "unsupported", At: time.Now().UTC()}
			defer func() { samples[i] = sample }()
			name, profile, _ := strings.Cut(t.Connection, "/")
			a, ok := providers.LookupAdapter(name)
			if !ok {
				return
			}
			reader, ok := a.(providers.PerformanceObserver)
			if !ok {
				return
			}
			c := credentials.Connection{Provider: name, Profile: profile}
			fields := credentials.Resolve(c, nil, nil, storepath.StoreFile(), true)
			if c.Require(fields) != nil {
				sample.Status = "missing_credentials"
				return
			}
			o := providers.ConnectionOptions(c, fields)
			o.CACertPath = opts.CACertPath
			o.SkipTLSVerify = opts.SkipTLSVerify
			o.Logger = opts.Logger
			observation, err := reader.ObservePerformance(ctx, o, t)
			if err != nil {
				sample.Status = readAccess(err)
				return
			}
			sample = observation
		})
	}
	wg.Wait()
	return samples
}
func SamplePerformance(ctx context.Context, opts NetworkMapOptions, input, interval string) (PerformanceReport, error) {
	targets, err := topology.ParsePerformancePath(input)
	if err != nil {
		return PerformanceReport{}, err
	}
	if len(opts.Connections) > 0 {
		return PerformanceReport{}, errors.New("select each connection in its path hop")
	}
	if interval == "" {
		interval = "5s"
	}
	d, err := time.ParseDuration(interval)
	if err != nil || d < time.Second || d > time.Minute {
		return PerformanceReport{}, errors.New("sample interval must be between one second and one minute")
	}
	report := PerformanceReport{Interval: d.String(), Start: time.Now().UTC()}
	a := samplePath(ctx, opts, targets)
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return PerformanceReport{}, ctx.Err()
	case <-timer.C:
	}
	b := samplePath(ctx, opts, targets)
	if err := ctx.Err(); err != nil {
		return PerformanceReport{}, err
	}
	report.End = time.Now().UTC()
	for i, t := range targets {
		report.Hops = append(report.Hops, topology.AssessHop(i+1, t.Kind, a[i], b[i]))
	}
	return report, nil
}
