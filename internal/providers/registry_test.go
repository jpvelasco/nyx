package providers_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/models"
	providers "github.com/jpvelasco/nyx/internal/providers"
)

type mockProvider struct{ name string }

func (m *mockProvider) Name() string           { return m.name }
func (m *mockProvider) Capabilities() []string { return []string{"info"} }
func (m *mockProvider) Info(ctx context.Context, opts providers.ImportOptions) (*providers.ProviderInfo, error) {
	return &providers.ProviderInfo{Provider: m.name}, nil
}
func (m *mockProvider) ImportSpec(ctx context.Context, opts providers.ImportOptions) (*providers.ImportResult, error) {
	return nil, &providers.ErrCapabilityUnsupported{Provider: m.name, Capability: "import"}
}
func (m *mockProvider) Check(ctx context.Context, opts providers.ImportOptions) (*providers.AuditResult, error) {
	return nil, &providers.ErrCapabilityUnsupported{Provider: m.name, Capability: "check"}
}
func (m *mockProvider) CheckACL(ctx context.Context, req providers.ACLCheckRequest, opts providers.ImportOptions) (*models.CheckResult, error) {
	return nil, &providers.ErrCapabilityUnsupported{Provider: m.name, Capability: "check_acl"}
}

func TestRegisterAndGet(t *testing.T) {
	providers.Reset()
	p := &mockProvider{name: "test"}
	if err := providers.Register(p); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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
	if err := providers.Register(&mockProvider{name: "a"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := providers.Register(&mockProvider{name: "b"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	list := providers.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 providers, got %d", len(list))
	}
}

func TestRegisterDuplicate(t *testing.T) {
	providers.Reset()
	p := &mockProvider{name: "dup"}
	if err := providers.Register(p); err != nil {
		t.Fatalf("first registration should succeed: %v", err)
	}
	if err := providers.Register(p); err == nil {
		t.Fatal("expected error on duplicate registration")
	}
}

func TestErrCapabilityUnsupported(t *testing.T) {
	providers.Reset()
	p := &mockProvider{name: "test"}
	ctx := context.Background()

	_, err := p.ImportSpec(ctx, providers.ImportOptions{})
	if err == nil {
		t.Fatal("expected error from ImportSpec")
	}
	msg := err.Error()
	if !strings.Contains(msg, "test") || !strings.Contains(msg, "import") {
		t.Errorf("unexpected error message: %q", msg)
	}

	_, err = p.Check(ctx, providers.ImportOptions{})
	if err == nil {
		t.Fatal("expected error from Check")
	}
	msg = err.Error()
	if !strings.Contains(msg, "test") || !strings.Contains(msg, "check") {
		t.Errorf("unexpected error message: %q", msg)
	}
}
