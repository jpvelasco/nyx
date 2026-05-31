package providers

import "sync"

var (
	mu       sync.RWMutex
	registry = map[string]Provider{}
)

// Register adds a provider to the registry. Panics on duplicate name.
func Register(p Provider) {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := registry[p.Name()]; exists {
		panic("provider already registered: " + p.Name())
	}
	registry[p.Name()] = p
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
