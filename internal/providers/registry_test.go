package providers_test

import (
	"context"
	"testing"

	providers "github.com/jpvelasco/nyx/internal/providers"
)

type mockProvider struct{ name string }

func (m *mockProvider) Name() string             { return m.name }
func (m *mockProvider) Capabilities() []string   { return []string{"info"} }
func (m *mockProvider) Info(ctx context.Context, opts providers.ImportOptions) (*providers.ProviderInfo, error) {
	return &providers.ProviderInfo{Provider: m.name}, nil
}
func (m *mockProvider) ImportSpec(ctx context.Context, opts providers.ImportOptions) (*providers.ImportResult, error) {
	return nil, &providers.ErrCapabilityUnsupported{Provider: m.name, Capability: "import"}
}
func (m *mockProvider) Check(ctx context.Context, opts providers.ImportOptions) (*providers.AuditResult, error) {
	return nil, &providers.ErrCapabilityUnsupported{Provider: m.name, Capability: "check"}
}

func TestRegisterAndGet(t *testing.T) {
	providers.Reset()
	p := &mockProvider{name: "test"}
	providers.Register(p)

	got := providers.Get("test")
	if got == nil {
		t.Fatal("expected provider, got nil")
	}
	if got.Name() != "test" {
		t.Fatalf("expected name 'test', got %q", got.Name())
	}
}

func TestGetUnknown(t *testing.T) {
	providers.Reset()
	got := providers.Get("unknown")
	if got != nil {
		t.Fatal("expected nil for unknown provider")
	}
}

func TestList(t *testing.T) {
	providers.Reset()
	providers.Register(&mockProvider{name: "a"})
	providers.Register(&mockProvider{name: "b"})
	list := providers.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 providers, got %d", len(list))
	}
}
