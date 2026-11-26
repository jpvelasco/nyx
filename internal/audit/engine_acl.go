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
	"github.com/jpvelasco/nyx/internal/storepath"
)

// aclCheckErrorResult creates a finished CheckResult with StatusError for acl_check failures.
func aclCheckErrorResult(provider, policy string, summary string) *models.CheckResult {
	result := models.NewCheckResult(provider, "acl_check", provider, policy)
	result.Status = models.StatusError
	result.Summary = summary
	result.Finish()
	return result
}

func (e *Engine) controllerOptions(providerName string) providers.ImportOptions {
	c := credentials.Connection{Provider: providerName, Profile: e.CredentialProfiles[providerName]}
	if existing, ok := e.ControllerOptions[providerName]; ok {
		return existing
	}
	path := e.CredentialsPath
	if path == "" {
		path = storepath.StoreFile()
	}
	opts := providers.ConnectionOptions(c, credentials.Resolve(c, nil, os.Getenv, path, true))
	opts.SkipTLSVerify, opts.CACertPath = e.SkipTLSVerify, e.CACertPath
	return opts
}

func (e *Engine) runACLCheck(ctx context.Context, a intent.Assertion) (*models.CheckResult, error) {
	providerName, err := e.Spec.AssertionProvider(a)
	if err != nil {
		return aclCheckErrorResult(a.Provider, a.Policy, err.Error()), nil
	}
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
	p, exists := providers.LookupAdapter(providerName)
	if !exists {
		return aclCheckErrorResult(providerName, a.Policy,
			fmt.Sprintf("provider %q not found in registry", providerName)), nil
	}

	checker, ok := p.(providers.ACLChecker)
	if !ok {
		return aclCheckErrorResult(providerName, a.Policy, fmt.Sprintf("provider %q does not support acl_check", providerName)), nil
	}

	// Build import options from environment (backward-compatible with existing env var pattern)
	opts := e.controllerOptions(providerName)
	if err := opts.Connection.Require(opts.Credentials); err != nil {
		if opts.Connection.ProfileName() != "default" || (providerName != "omada" && providerName != "opnsense") {
			return aclCheckErrorResult(providerName, a.Policy, "acl_check requires provider credentials: "+err.Error()), nil
		}
		if providerName == "opnsense" {
			return aclCheckErrorResult(providerName, a.Policy, "acl_check requires OPNSENSE_HOST, OPNSENSE_API_KEY, OPNSENSE_API_SECRET or stored credentials"), nil
		}
		hint := credmanager.Hint(opts.Host)
		return aclCheckErrorResult(providerName, a.Policy, "acl_check requires OMADA_HOST, OMADA_CLIENT_ID, OMADA_CLIENT_SECRET environment variables"+hint+", or stored credentials (see `nyx credentials set omada`)"), nil
	}

	expect := a.Expect // "enforced" or "not_enforced"
	wantEnforced := expect == "enforced"

	req := providers.ACLCheckRequest{
		PolicyName:          a.Policy,
		From:                policy.From,
		To:                  policy.To,
		Action:              policy.Action,
		ExpectEnforced:      wantEnforced,
		ExpectBidirectional: a.ExpectBidirectional,
	}

	result, err := checker.CheckACL(ctx, req, opts)
	return result, opts.Connection.RedactError(err, opts.Credentials)
}
