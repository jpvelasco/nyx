package service

import (
	"context"
	"github.com/jpvelasco/nyx/internal/credentials"
	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/testutil/providerfixture"
	"github.com/jpvelasco/nyx/internal/topology"
	"path/filepath"
	"testing"
	"time"
)

type metricFixture struct {
	providerfixture.ReadOnlyAdapter
}

func (*metricFixture) Capabilities() []string { return []string{providers.PerformanceCapability} }
func (f *metricFixture) ObservePerformance(_ context.Context, _ providers.ImportOptions, _ topology.PerformanceTarget) (topology.PassiveSample, error) {
	f.Calls++
	count := uint64(f.Calls)
	return topology.PassiveSample{At: time.Now(), Status: "available", RxErrors: &count}, f.Err
}
func TestSampleSelectedPerformancePath(t *testing.T) {
	providerfixture.IsolateProviders(t)
	f := &metricFixture{}
	if err := providers.Register(f); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "credentials.json")
	t.Setenv("NYX_CREDENTIALS_FILE", path)
	store, err := credentials.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set("synthetic", "home", credentials.Entry{"host": "controller.example", "api_key": "key"}); err != nil {
		t.Fatal(err)
	}
	const target = `[{"connection":"synthetic/home","kind":"interface","name":"example"}]`
	ctx := t.Context()
	report, err := SamplePerformance(ctx, NetworkMapOptions{}, target, "1s")
	if err != nil || len(report.Hops) != 1 || f.Calls != 2 || report.Hops[0].Finding == "" {
		t.Fatalf("same-window evidence: %v %v", report, err)
	}
	for _, tc := range []struct {
		input, interval string
		opts            NetworkMapOptions
	}{{"bad", "", NetworkMapOptions{}}, {target, "0s", NetworkMapOptions{}}, {target, "1s", NetworkMapOptions{Connections: []string{"synthetic/home"}}}} {
		if _, err := SamplePerformance(ctx, tc.opts, tc.input, tc.interval); err == nil {
			t.Fatal("invalid path input")
		}
	}
	c, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := SamplePerformance(c, NetworkMapOptions{}, target, "1s"); err == nil {
		t.Fatal("lost cancellation")
	}
	f.Err = permissionStatus(403)
	samples := samplePath(ctx, NetworkMapOptions{}, []topology.PerformanceTarget{{Connection: "synthetic/home"}, {Connection: "absent/home"}, {Connection: "synthetic/missing"}})
	if samples[0].Status != "permission_denied" || samples[1].Status != "unsupported" || samples[2].Status != "missing_credentials" {
		t.Fatal(samples)
	}
}
