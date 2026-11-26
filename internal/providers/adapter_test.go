package providers_test

import (
	"context"
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
