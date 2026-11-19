package audit

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/providers"
)

// --- runACLCheck ---

func TestRunACLCheck_PolicyNotFound(t *testing.T) {
	spec := &intent.Spec{Version: 1, Site: "test"}
	a := intent.Assertion{Type: "acl_check", Provider: "omada", Policy: "missing-policy", Expect: "enforced"}
	eng := NewEngine(spec)
	result, err := eng.runACLCheck(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusError {
		t.Errorf("expected error for missing policy, got %s", result.Status)
	}
}

func TestRunACLCheck_OpnsenseEdge(t *testing.T) {
	providers.Reset()
	t.Cleanup(providers.Reset)
	rec := &recordingEdgeACLProvider{}
	if err := providers.Register(rec); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPNSENSE_HOST", "firewall.example")
	t.Setenv("OPNSENSE_API_KEY", "fixture-key")
	t.Setenv("OPNSENSE_API_SECRET", "fixture-secret")
	eng := NewEngine(&intent.Spec{Networks: []intent.Network{{Name: "trusted", Edge: "opnsense", Observer: "omada"}}, Policies: []intent.Policy{{Name: "deny-egress", From: "trusted", To: "internet", Action: "deny"}}})
	a := intent.Assertion{Type: "acl_check", Network: "trusted", Policy: "deny-egress", Expect: "enforced"}
	result, err := eng.runACLCheck(t.Context(), a)
	if err != nil || result.Status != models.StatusPass || rec.opts.Host != "firewall.example" || rec.req.From != "trusted" {
		t.Fatalf("unexpected edge result=%+v err=%v", result, err)
	}
	a.Provider = "omada"
	result, err = eng.runACLCheck(t.Context(), a)
	if err != nil || result.Status != models.StatusError {
		t.Fatalf("expected provider conflict: result=%+v err=%v", result, err)
	}
	t.Setenv("OPNSENSE_HOST", "")
	eng.CredentialsPath = filepath.Join(t.TempDir(), "credentials.json")
	a.Provider = ""
	result, err = eng.runACLCheck(t.Context(), a)
	if err != nil || !strings.Contains(result.Summary, "OPNSENSE_HOST") {
		t.Fatalf("expected OPNsense credential error, result=%+v err=%v", result, err)
	}
}

type recordingEdgeACLProvider struct {
	aclTestProviderWithResult
	opts providers.ImportOptions
	req  providers.ACLCheckRequest
}

func (*recordingEdgeACLProvider) Name() string { return "opnsense" }

func (p *recordingEdgeACLProvider) CheckACL(ctx context.Context, req providers.ACLCheckRequest, opts providers.ImportOptions) (*models.CheckResult, error) {
	p.req, p.opts = req, opts
	return p.aclTestProviderWithResult.CheckACL(ctx, req, opts)
}
