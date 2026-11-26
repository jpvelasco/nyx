package providers_test

import (
	"context"
	"github.com/jpvelasco/nyx/internal/testutil/providerfixture"
	"testing"

	"github.com/jpvelasco/nyx/internal/providers"
)

type adapter struct {
	name       string
	operations []string
}

func (a adapter) Name() string           { return a.name }
func (a adapter) Capabilities() []string { return a.operations }

type infoAdapter struct{ adapter }

func (a infoAdapter) Info(context.Context, providers.ImportOptions) (*providers.ProviderInfo, error) {
	return &providers.ProviderInfo{Provider: a.Name()}, nil
}
func TestPartialAdapterRegistration(t *testing.T) {
	providers.Reset()
	t.Cleanup(providers.Reset)
	a := infoAdapter{adapter{"synthetic", []string{"info"}}}
	if err := providers.Register(a); err != nil {
		t.Fatal(err)
	}
	got, ok := providers.LookupAdapter(a.Name())
	if !ok || got.Name() != a.Name() || len(providers.Adapters()) != 1 {
		t.Fatalf("missing adapter: %v", got)
	}
	if providers.Get(a.Name()) != nil || len(providers.List()) != 0 {
		t.Fatal("info adapter appeared in legacy full-provider view")
	}
	for _, bad := range []adapter{{"broken", []string{"info"}}, {"", nil}, {"bad name", nil}, {"incomplete", []string{"import"}}} {
		if err := providers.Register(bad); err == nil {
			t.Errorf("registered incompatible adapter %q", bad.Name())
		}
	}
}

func TestDeclaredRolesAndOperationRequirements(t *testing.T) {
	providerfixture.IsolateProviders(t)
	a := new(providerfixture.ReadOnlyAdapter)
	if err := providers.Register(a); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"observer", "edge", "acl_check", "acl_drift", "nat_check", "wlan_schedule_liveness"} {
		if providers.Specs("synthetic", role) != (role == "observer") {
			t.Errorf("unexpected role %s", role)
		}
	}
	if providers.Specs("absent", "observer") {
		t.Fatal("accepted unknown adapter")
	}
	if err := providers.Register(&mockProvider{name: "legacy"}); err != nil {
		t.Fatal(err)
	}
	if !providers.Specs("legacy", "acl_check") || providers.Specs("legacy", "edge") {
		t.Fatal("incorrect legacy role projection")
	}
	if err := providers.Register(adapter{"inventoryonly", []string{"inventory"}}); err == nil {
		t.Fatal("accepted missing inventory reader")
	}
	if err := providers.Register(a); err == nil {
		t.Fatal("accepted duplicate adapter")
	}
	if err := providers.Register(nil); err == nil {
		t.Fatal("accepted nil adapter")
	}
}
