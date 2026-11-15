package audit

import (
	"context"
	"fmt"
	"os"

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
	providerName := a.Provider
	p := providers.Get(providerName)
	if p == nil {
		return natCheckErrorResult(providerName, fmt.Sprintf("provider %q not found in registry", providerName)), nil
	}
	checker, ok := p.(providers.NatChecker)
	if !ok {
		return natCheckErrorResult(providerName,
			fmt.Sprintf("provider %q does not support nat_check", providerName)), nil
	}

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
	if opts.Host == "" || opts.ClientID == "" || opts.ClientSecret == "" {
		hint := ""
		if providerName == "omada" {
			hint = credmanager.Hint(opts.Host)
		}
		return natCheckErrorResult(providerName,
			"nat_check requires provider credentials: environment variables (OMADA_* / OPNSENSE_*)"+
				hint+" or stored credentials (see `nyx credentials set <provider>`)"), nil
	}

	return checker.NatCheck(ctx, providers.NatCheckRequest{ExpectMode: a.NatMode}, opts)
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
