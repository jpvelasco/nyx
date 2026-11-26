// Package providerfixture supplies synthetic registered adapters for transport tests.
package providerfixture

import (
	"context"
	"testing"

	"github.com/jpvelasco/nyx/internal/credentials"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/providers"
)

// IsolateProviders restores the registered adapters and credential schemas after a test.
func IsolateProviders(t *testing.T) {
	t.Helper()
	previous := providers.Adapters()
	providers.Reset()
	t.Cleanup(func() {
		providers.Reset()
		for _, p := range previous {
			if err := providers.Register(p); err != nil {
				t.Error(err)
			}
		}
	})
}

// ReadOnlyAdapter implements only metadata reads and the observer role.
type ReadOnlyAdapter struct {
	Calls int
	Err   error
}

func (*ReadOnlyAdapter) Name() string                      { return "synthetic" }
func (*ReadOnlyAdapter) Capabilities() []string            { return []string{"info"} }
func (*ReadOnlyAdapter) SupportsSpecRole(role string) bool { return role == intent.RoleObserver }
func (*ReadOnlyAdapter) CredentialFields() []credentials.Field {
	return []credentials.Field{{Name: "host", Env: "SYNTHETIC_HOST", Required: true}, {Name: "api_key", Env: "SYNTHETIC_API_KEY", Secret: true, Required: true}}
}
func (p *ReadOnlyAdapter) Info(_ context.Context, opts providers.ImportOptions) (*providers.ProviderInfo, error) {
	p.Calls++
	if p.Err != nil {
		return nil, p.Err
	}
	return &providers.ProviderInfo{Provider: p.Name(), Host: opts.Host, Version: "test"}, nil
}
