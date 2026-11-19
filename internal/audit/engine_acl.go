package audit

import (
	"context"
	"fmt"
	"os"

	"github.com/jpvelasco/nyx/internal/credentials"
	"github.com/jpvelasco/nyx/internal/credentials/credmanager"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	providers "github.com/jpvelasco/nyx/internal/providers"
)

// aclCheckErrorResult creates a finished CheckResult with StatusError for acl_check failures.
func aclCheckErrorResult(provider, policy string, summary string) *models.CheckResult {
	result := models.NewCheckResult(provider, "acl_check", provider, policy)
	result.Status = models.StatusError
	result.Summary = summary
	result.Finish()
	return result
}

// fillFromCredentialStores completes missing import options from the
// Windows Credential Manager (omada only; no-op off Windows — the entry
// nyx-omada-<host> is keyed on the resolved host, which this step can
// never supply) and then the encrypted credential store (entry
// <provider>/default). Store failures are silently ignored — env vars
// remain the primary source and the caller still reports missing
// credentials.
func fillFromCredentialStores(opts providers.ImportOptions, provider, path string) providers.ImportOptions {
	if provider == "omada" {
		opts.ClientID, opts.ClientSecret = credmanager.OverlayOmada(opts.Host, opts.ClientID, opts.ClientSecret)
	}
	fields := credentials.Fields{
		Host:         opts.Host,
		ClientID:     opts.ClientID,
		ClientSecret: opts.ClientSecret,
		Site:         opts.Site,
	}
	if provider == "opnsense" {
		fields.APIKey, fields.APISecret = credmanager.OverlayOpnsense(opts.Host, opts.ClientID, opts.ClientSecret)
	}
	credentials.Overlay(path, provider, "default", &fields)
	if provider == "opnsense" {
		fields.ClientID, fields.ClientSecret = fields.APIKey, fields.APISecret
	}
	opts.Host = fields.Host
	opts.ClientID = fields.ClientID
	opts.ClientSecret = fields.ClientSecret
	opts.Site = fields.Site
	return opts
}

func (e *Engine) controllerOptions(providerName string) providers.ImportOptions {
	opts := providers.ImportOptions{
		Host:          os.Getenv("OMADA_HOST"),
		ClientID:      os.Getenv("OMADA_CLIENT_ID"),
		ClientSecret:  os.Getenv("OMADA_CLIENT_SECRET"),
		Site:          os.Getenv("OMADA_SITE"),
		SkipTLSVerify: e.SkipTLSVerify,
		CACertPath:    e.CACertPath,
	}
	if providerName == "opnsense" {
		// OPNsense env vars carry the API key/secret pair in the generic
		// ClientID/ClientSecret fields.
		opts.Host = os.Getenv("OPNSENSE_HOST")
		opts.ClientID = os.Getenv("OPNSENSE_API_KEY")
		opts.ClientSecret = os.Getenv("OPNSENSE_API_SECRET")
		opts.Site = ""
	}
	if opts.Host == "" || opts.ClientID == "" || opts.ClientSecret == "" {
		opts = fillFromCredentialStores(opts, providerName, e.CredentialsPath)
	}
	return opts
}

func (e *Engine) runACLCheck(ctx context.Context, a intent.Assertion) (*models.CheckResult, error) {
	providerName := a.Provider
	if providerName == "" {
		providerName = "omada"
	}

	// Find the declared policy in the spec
	var policy *intent.Policy
	for i := range e.Spec.Policies {
		if e.Spec.Policies[i].Name == a.Policy {
			policy = &e.Spec.Policies[i]
			break
		}
	}
	if policy == nil {
		return aclCheckErrorResult(providerName, a.Policy,
			fmt.Sprintf("policy %q not found in spec", a.Policy)), nil
	}

	// Look up provider from registry
	p := providers.Get(providerName)
	if p == nil {
		return aclCheckErrorResult(providerName, a.Policy,
			fmt.Sprintf("provider %q not found in registry", providerName)), nil
	}

	// Build import options from environment (backward-compatible with existing env var pattern)
	opts := e.controllerOptions(providerName)
	if opts.Host == "" || opts.ClientID == "" || opts.ClientSecret == "" {
		if providerName == "opnsense" {
			return aclCheckErrorResult(providerName, a.Policy, "acl_check requires OPNSENSE_HOST, OPNSENSE_API_KEY, OPNSENSE_API_SECRET or stored credentials"), nil
		}
		hint := ""
		if providerName == "omada" {
			hint = credmanager.Hint(opts.Host)
		}
		return aclCheckErrorResult(providerName, a.Policy,
			"acl_check requires OMADA_HOST, OMADA_CLIENT_ID, OMADA_CLIENT_SECRET environment variables"+
				hint+", or stored credentials (see `nyx credentials set omada`)"), nil
	}

	expect := a.Expect // "enforced" or "not_enforced"
	wantEnforced := expect == "enforced"

	req := providers.ACLCheckRequest{
		PolicyName:     a.Policy,
		From:           policy.From,
		To:             policy.To,
		Action:         policy.Action,
		ExpectEnforced: wantEnforced,
	}

	return p.CheckACL(ctx, req, opts)
}
