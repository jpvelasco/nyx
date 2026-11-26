package audit

import (
	"context"
	"fmt"

	"github.com/jpvelasco/nyx/internal/credentials/credmanager"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	providers "github.com/jpvelasco/nyx/internal/providers"
)

// runNatCheck evaluates the nat_check assertion against the live NAT
// posture of the named provider. It is assertion-on-reads: the provider
// only ever performs reads, so the verdict is decoupled from the mutation
// path. Credentials resolve env → store, like acl_check; missing
// credentials surface as a StatusError result, never a Go error.
func (e *Engine) runNatCheck(ctx context.Context, a intent.Assertion) (*models.CheckResult, error) {
	providerName, err := e.Spec.AssertionProvider(a)
	if err != nil {
		return natCheckErrorResult(a.Provider, err.Error()), nil
	}
	p, exists := providers.LookupAdapter(providerName)
	if !exists {
		return natCheckErrorResult(providerName, fmt.Sprintf("provider %q not found in registry", providerName)), nil
	}
	checker, ok := p.(providers.NatChecker)
	if !ok {
		return natCheckErrorResult(providerName,
			fmt.Sprintf("provider %q does not support nat_check", providerName)), nil
	}

	opts := e.controllerOptions(providerName)
	if err := opts.Connection.Require(opts.Credentials); err != nil {
		if opts.Connection.ProfileName() != "default" || (providerName != "omada" && providerName != "opnsense") {
			return natCheckErrorResult(providerName, "nat_check requires provider credentials: "+err.Error()), nil
		}
		hint := ""
		if providerName == "omada" {
			hint = credmanager.Hint(opts.Host)
		}
		return natCheckErrorResult(providerName,
			"nat_check requires provider credentials: environment variables (OMADA_* / OPNSENSE_*)"+
				hint+" or stored credentials (see `nyx credentials set <provider>`)"), nil
	}

	result, err := checker.NatCheck(ctx, providers.NatCheckRequest{ExpectMode: a.NatMode}, opts)
	return result, opts.Connection.RedactError(err, opts.Credentials)
}

// natCheckErrorResult creates a finished CheckResult with StatusError for
// nat_check failures.
func natCheckErrorResult(provider, summary string) *models.CheckResult {
	result := models.NewCheckResult(provider, "nat_check", provider, "")
	result.Status = models.StatusError
	result.Summary = summary
	result.Finish()
	return result
}
