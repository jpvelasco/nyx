package service

import (
	"context"
	"errors"
	"github.com/jpvelasco/nyx/internal/credentials"
	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/testutil/providerfixture"
	"github.com/jpvelasco/nyx/internal/topology"
	"path/filepath"
	"slices"
	"testing"
)

type clientReaderFixture struct {
	providerfixture.ReadOnlyAdapter
}

func (*clientReaderFixture) Capabilities() []string {
	return []string{providers.NetworkMapCapability, providers.ClientLocationCapability}
}
func (*clientReaderFixture) ObserveNetwork(context.Context, providers.ImportOptions) (topology.ObservationSet, error) {
	return topology.ObservationSet{Resources: []topology.Observation{{Ref: topology.ResourceRef{Kind: "port", Key: "switch/8"}, Port: 8}}}, nil
}
func (a *clientReaderFixture) ObserveClient(context.Context, providers.ImportOptions, string) ([]topology.ClientObservation, []string, error) {
	a.Calls++
	return []topology.ClientObservation{{Kind: "association", Status: "current", Attachment: topology.ResourceRef{Kind: "port", Key: "switch/8"}}}, nil, a.Err
}
func TestLocateClientSelectorsAndPartialEvidence(t *testing.T) {
	providerfixture.IsolateProviders(t)
	f := &clientReaderFixture{}
	if err := providers.Register(f); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "credentials.json")
	t.Setenv("NYX_CREDENTIALS_FILE", p)
	store, err := credentials.Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set("synthetic", "home", credentials.Entry{"host": "controller.example", "api_key": "key"}); err != nil {
		t.Fatal(err)
	}
	svc := NewTopologyService()
	opts := NetworkMapOptions{Connections: []string{"synthetic/home"}}
	for _, bad := range []string{"bad", "00:00:00:00:00:00", "01:aa:bb:cc:dd:01"} {
		if _, err := svc.LocateClient(t.Context(), opts, bad); err == nil {
			t.Fatal("accepted invalid MAC")
		}
	}
	f.Err = permissionStatus(403)
	r, err := svc.LocateClient(t.Context(), opts, "02:aa:bb:cc:dd:04")
	if err != nil || r.Status != "located" || f.Calls != 1 || !slices.Contains(r.Path.Sources[0].Gaps, "client evidence permission_denied") {
		t.Fatal(r, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := svc.LocateClient(ctx, opts, "02:aa:bb:cc:dd:04"); !errors.Is(err, context.Canceled) {
		t.Fatal("lost cancellation")
	}
}
