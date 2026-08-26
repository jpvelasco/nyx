package audit

import (
	"context"
	"testing"

	"github.com/jpvelasco/nyx/internal/credentials"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	providers "github.com/jpvelasco/nyx/internal/providers"
)

// natTestProvider is a registry stub implementing the nat_check surface only.
// name defaults to "nattest" unless overridden, so tests can register it under
// a real provider name (e.g. "opnsense") to exercise the engine's per-provider
// credential mapping.
type natTestProvider struct {
	name   string
	called bool
	req    providers.NatCheckRequest
	opts   providers.ImportOptions
}

func (n *natTestProvider) Name() string {
	if n.name != "" {
		return n.name
	}
	return "nattest"
}
func (n *natTestProvider) Capabilities() []string { return []string{"nat_check"} }
func (n *natTestProvider) Info(ctx context.Context, opts providers.ImportOptions) (*providers.ProviderInfo, error) {
	return nil, nil
}
func (n *natTestProvider) ImportSpec(ctx context.Context, opts providers.ImportOptions) (*providers.ImportResult, error) {
	return nil, nil
}
func (n *natTestProvider) Check(ctx context.Context, opts providers.ImportOptions) (*providers.AuditResult, error) {
	return nil, nil
}
func (n *natTestProvider) CheckACL(ctx context.Context, req providers.ACLCheckRequest, opts providers.ImportOptions) (*models.CheckResult, error) {
	return nil, nil
}
func (n *natTestProvider) NatCheck(ctx context.Context, req providers.NatCheckRequest, opts providers.ImportOptions) (*models.CheckResult, error) {
	n.called = true
	n.req = req
	n.opts = opts
	return &models.CheckResult{Status: models.StatusPass}, nil
}

func TestRunNatCheck_ProviderNotFound(t *testing.T) {
	providers.Reset()
	t.Cleanup(func() { providers.Reset() })

	eng := NewEngine(&intent.Spec{Version: 1, Site: "test"})
	result, err := eng.runNatCheck(context.Background(), intent.Assertion{
		Type: "nat_check", Provider: "nonexistent", NatMode: "disabled",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusError || result.CheckType != "nat_check" {
		t.Errorf("got %s/%s, want error/nat_check", result.CheckType, result.Status)
	}
}

func TestRunNatCheck_ProviderLacksNatChecker(t *testing.T) {
	providers.Reset()
	t.Cleanup(func() { providers.Reset() })
	if err := providers.Register(&aclTestProvider{}); err != nil {
		t.Fatalf("register: %v", err)
	}

	eng := NewEngine(&intent.Spec{Version: 1, Site: "test"})
	result, err := eng.runNatCheck(context.Background(), intent.Assertion{
		Type: "nat_check", Provider: "acltest", NatMode: "disabled",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusError {
		t.Errorf("status = %s, want error for provider without nat_check", result.Status)
	}
}

// opnsense-style env vars must land in the generic ClientID/ClientSecret
// fields so the provider's BasicAuth wiring works.
func TestRunNatCheck_OpnsenseEnvMapping(t *testing.T) {
	providers.Reset()
	t.Cleanup(func() { providers.Reset() })
	// Register under the real provider name so the engine's per-provider
	// OPNSENSE_* → ClientID/ClientSecret mapping is what gets exercised.
	rec := &natTestProvider{name: "opnsense"}
	if err := providers.Register(rec); err != nil {
		t.Fatalf("register: %v", err)
	}

	t.Setenv("OMADA_HOST", "")
	t.Setenv("OMADA_CLIENT_ID", "")
	t.Setenv("OMADA_CLIENT_SECRET", "")
	t.Setenv("OPNSENSE_HOST", "fw.example")
	t.Setenv("OPNSENSE_API_KEY", "key")
	t.Setenv("OPNSENSE_API_SECRET", "secret")

	eng := NewEngine(&intent.Spec{Version: 1, Site: "test"})
	result, err := eng.runNatCheck(context.Background(), intent.Assertion{
		Type: "nat_check", Provider: "opnsense", NatMode: "disabled",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !rec.called {
		t.Fatal("NatCheck was not called; credential gate likely blocked")
	}
	if result.Status != models.StatusPass {
		t.Errorf("status = %s, want pass", result.Status)
	}
	if rec.opts.Host != "fw.example" || rec.opts.ClientID != "key" || rec.opts.ClientSecret != "secret" {
		t.Errorf("opts = %+v, want opnsense env mapping", rec.opts)
	}
	if rec.req.ExpectMode != "disabled" {
		t.Errorf("ExpectMode = %q, want disabled", rec.req.ExpectMode)
	}
}

func TestRunNatCheck_VaultFallback(t *testing.T) {
	providers.Reset()
	t.Cleanup(func() { providers.Reset() })
	rec := &natTestProvider{}
	if err := providers.Register(rec); err != nil {
		t.Fatalf("register: %v", err)
	}

	t.Setenv("OMADA_HOST", "")
	t.Setenv("OMADA_CLIENT_ID", "")
	t.Setenv("OMADA_CLIENT_SECRET", "")
	t.Setenv("OPNSENSE_HOST", "")
	t.Setenv("OPNSENSE_API_KEY", "")
	t.Setenv("OPNSENSE_API_SECRET", "")

	storePath := t.TempDir() + "/credentials.json"
	store, err := credentials.Open(storePath)
	if err != nil {
		t.Fatalf("credentials.Open failed: %v", err)
	}
	if err := store.Set("nattest", "default", credentials.Entry{
		"host":          "10.0.0.9",
		"client_id":     "vault-user",
		"client_secret": "vault-pass",
	}); err != nil {
		t.Fatalf("store.Set failed: %v", err)
	}

	eng := NewEngine(&intent.Spec{Version: 1, Site: "test"})
	eng.CredentialsPath = storePath
	result, err := eng.runNatCheck(context.Background(), intent.Assertion{
		Type: "nat_check", Provider: "nattest", NatMode: "bridge",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !rec.called {
		t.Fatalf("NatCheck was not called; vault fallback failed (status %s: %s)", result.Status, result.Summary)
	}
	if rec.opts.Host != "10.0.0.9" || rec.opts.ClientID != "vault-user" {
		t.Errorf("opts = %+v, want vault values", rec.opts)
	}
}

// A provider with neither env nor stored credentials must surface a
// StatusError naming the credential requirement — mirroring acl_check.
func TestRunNatCheck_VaultEmptyStillErrors(t *testing.T) {
	providers.Reset()
	t.Cleanup(func() { providers.Reset() })

	t.Setenv("OMADA_HOST", "")
	t.Setenv("OMADA_CLIENT_ID", "")
	t.Setenv("OMADA_CLIENT_SECRET", "")
	t.Setenv("OPNSENSE_HOST", "")
	t.Setenv("OPNSENSE_API_KEY", "")
	t.Setenv("OPNSENSE_API_SECRET", "")

	rec := &natTestProvider{}
	if err := providers.Register(rec); err != nil {
		t.Fatalf("register: %v", err)
	}
	eng := NewEngine(&intent.Spec{Version: 1, Site: "test"})
	eng.CredentialsPath = t.TempDir() + "/empty.json"
	result, err := eng.runNatCheck(context.Background(), intent.Assertion{
		Type: "nat_check", Provider: "nattest", NatMode: "bridge",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rec.called {
		t.Fatal("NatCheck must not be called without credentials")
	}
	if result.Status != models.StatusError {
		t.Errorf("status = %s, want error", result.Status)
	}
	if !contains(result.Summary, "requires") {
		t.Errorf("summary %q should contain 'requires' for the CLI recommendations filter", result.Summary)
	}
}
