package providers

import (
	"fmt"
	"sync"

	"github.com/jpvelasco/nyx/internal/credentials"
)

var (
	mu       sync.RWMutex
	registry = map[string]Provider{}
)

// CredentialDescriber lets new adapters declare their credential fields.
type CredentialDescriber interface{ CredentialFields() []credentials.Field }

// Register adds a provider to the registry. Returns an error on duplicate name.
func Register(p Provider) error {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := registry[p.Name()]; exists {
		return fmt.Errorf("provider already registered: %s", p.Name())
	}
	if d, ok := p.(CredentialDescriber); ok {
		if err := credentials.RegisterFields(p.Name(), d.CredentialFields()); err != nil {
			return err
		}
	}
	registry[p.Name()] = p
	return nil
}

// Get returns the provider with the given name, or nil if not found.
func Get(name string) Provider {
	mu.RLock()
	defer mu.RUnlock()
	return registry[name]
}

// List returns all registered providers in arbitrary order.
func List() []Provider {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Provider, 0, len(registry))
	for _, p := range registry {
		out = append(out, p)
	}
	return out
}

// Reset clears the registry. For testing only.
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	registry = map[string]Provider{}
	credentials.ClearRegisteredFields()
}
