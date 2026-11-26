package providers

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/jpvelasco/nyx/internal/credentials"
	"github.com/jpvelasco/nyx/internal/intent"
)

// Adapter is the common registration contract. Operations are optional typed interfaces.
type Adapter interface {
	Name() string
	Capabilities() []string
}

var (
	mu        sync.RWMutex
	registry  = map[string]Adapter{}
	validName = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)
	// Specs validates against the adapters compiled into the running distribution.
	Specs intent.ProviderLookup = supportsRole
)

// CredentialDescriber lets new adapters declare their credential fields.
type CredentialDescriber interface{ CredentialFields() []credentials.Field }

// Register adds an adapter once. Reject an advertised operation if its implementation is absent.
func Register(p Adapter) error {
	if p == nil || !validName.MatchString(p.Name()) {
		return fmt.Errorf("invalid provider name")
	}
	for _, capability := range p.Capabilities() {
		var supported bool
		switch capability {
		case "info":
			_, supported = p.(InfoReader)
		case "inventory":
			_, supported = p.(InventoryProvider)
		case "check", "import":
			_, supported = p.(Provider)
		default:
			continue
		}
		if !supported {
			return &ErrCapabilityUnsupported{Provider: p.Name(), Capability: capability}
		}
	}
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

// LookupAdapter returns the concrete adapter, including operation-only implementations.
func LookupAdapter(name string) (Adapter, bool) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := registry[name]
	return p, ok
}

// Adapters returns the compiled-in adapters in provider-name order.
func Adapters() []Adapter {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Adapter, 0, len(registry))
	for _, p := range registry {
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b Adapter) int { return strings.Compare(a.Name(), b.Name()) })
	return out
}

// Get returns a legacy provider, or nil if it does not implement the full interface.
func Get(name string) Provider {
	p, _ := LookupAdapter(name)
	legacy, _ := p.(Provider)
	return legacy
}

// List returns the legacy full-provider view of the registry.
func List() []Provider {
	var out []Provider
	for _, p := range Adapters() {
		if legacy, ok := p.(Provider); ok {
			out = append(out, legacy)
		}
	}
	return out
}

// Reset clears the registry. For testing only.
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	clear(registry)
	credentials.ClearRegisteredFields()
}

// SpecRoleDeclarer supplies the network roles and optional enforcement semantics of an adapter.
type SpecRoleDeclarer interface{ SupportsSpecRole(string) bool }

func supportsRole(name, role string) bool {
	p, ok := LookupAdapter(name)
	if !ok {
		return false
	}
	switch role {
	case "acl_check":
		_, ok = p.(ACLChecker)
	case "acl_drift":
		_, ok = p.(ACLObserver)
	case "nat_check":
		_, ok = p.(NatChecker)
	case "wlan_schedule_liveness":
		_, ok = p.(WLANScheduleObserver)
	default:
		if spec, declared := p.(SpecRoleDeclarer); declared {
			return spec.SupportsSpecRole(role)
		}
		return intent.BuiltinProviderRole(name, role)
	}
	return ok
}
