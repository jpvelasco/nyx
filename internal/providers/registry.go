package providers

import (
	"fmt"
	"sync"
)

var (
	mu       sync.RWMutex
	registry = map[string]Provider{}
)

// Register adds a provider to the registry. Returns an error on duplicate name.
func Register(p Provider) error {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := registry[p.Name()]; exists {
		return fmt.Errorf("provider already registered: %s", p.Name())
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
}
