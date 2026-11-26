package service

import (
	"context"
	"errors"
	"github.com/jpvelasco/nyx/internal/credentials"
	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/testutil/providerfixture"
	"github.com/jpvelasco/nyx/internal/topology"
	"net/http"
	"path/filepath"
	"slices"
	"testing"
)

type mapTestReader struct {
	providerfixture.ReadOnlyAdapter
}

func (*mapTestReader) Capabilities() []string { return []string{providers.NetworkMapCapability} }
func (a *mapTestReader) ObserveNetwork(_ context.Context, o providers.ImportOptions) (topology.ObservationSet, error) {
	a.Calls++
	return topology.ObservationSet{ControllerSite: o.Site, Resources: []topology.Observation{{Ref: topology.ResourceRef{Kind: "switch", Key: "private-switch"}}}}, a.Err
}
func TestNetworkMapConnectionAvailability(t *testing.T) {
	providerfixture.IsolateProviders(t)
	t.Setenv("SYNTHETIC_HOST", "")
	t.Setenv("SYNTHETIC_API_KEY", "")
	path := filepath.Join(t.TempDir(), "credentials.json")
	t.Setenv("NYX_CREDENTIALS_FILE", path)
	ctx := t.Context()
	svc := NewTopologyService()
	if _, err := svc.Map(ctx, NetworkMapOptions{}); err == nil {
		t.Fatal("no sources")
	}
	reader := new(mapTestReader)
	if err := providers.Register(reader); err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"", "synthetic/", "absent"} {
		if _, err := svc.Map(ctx, NetworkMapOptions{Connections: []string{s}}); err == nil {
			t.Fatal("accepted selector", s)
		}
	}
	m, err := svc.Map(ctx, NetworkMapOptions{Connections: []string{"synthetic", "synthetic/default"}})
	if err != nil || len(m.Sources) != 1 || !slices.Contains(m.Sources[0].Gaps, "missing_credentials") {
		t.Fatal(m, err)
	}
	store, err := credentials.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set("synthetic", "home", credentials.Entry{"host": "controller.example", "api_key": "secret", "site": "fixture-site", "logical_site": "management"}); err != nil {
		t.Fatal(err)
	}
	reader.Err = permissionStatus(http.StatusForbidden)
	m, err = svc.Map(ctx, NetworkMapOptions{Detail: true})
	if err != nil || reader.Calls != 1 || len(m.Sources) != 1 || m.Sources[0].Profile != "home" || m.Sources[0].LogicalSite != "management" || len(m.Resources) != 1 || !slices.Contains(m.Sources[0].Gaps, "permission_denied") {
		t.Fatal(m, err)
	}
	bad, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := svc.Map(bad, NetworkMapOptions{Connections: []string{"synthetic"}}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost")
	}
	providers.Reset()
	if err := providers.Register(&providerfixture.ReadOnlyAdapter{}); err != nil {
		t.Fatal(err)
	}
	m, err = svc.Map(ctx, NetworkMapOptions{Connections: []string{"synthetic"}})
	if err != nil || !slices.Contains(m.Sources[0].Gaps, "unsupported") {
		t.Fatal(m, err)
	}
}
