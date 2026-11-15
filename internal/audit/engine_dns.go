package audit

import (
	"context"
	"fmt"

	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
)

func (e *Engine) runDNSCheck(ctx context.Context, a intent.Assertion) (*models.CheckResult, error) {
	var result *models.CheckResult
	var err error

	if a.ExpectIP != "" {
		result, err = e.Backend.ResolveExpect(ctx, a.Query, a.Server, a.ExpectIP)
	} else {
		result, err = e.Backend.Resolve(ctx, a.Query, a.Server)
	}
	if err != nil {
		return nil, fmt.Errorf("dns check failed: %w", err)
	}

	if result.Expected == nil {
		result.Expected = map[string]interface{}{}
	}
	result.Expected["query"] = a.Query

	if a.DNSSEC {
		dnssecResult, dnssecErr := e.Backend.CheckDNSSEC(ctx, a.Query, a.Server)
		if dnssecErr != nil {
			// The validator could not run at all. A requested validation
			// must not silently read as a validated pass: the finding
			// escalates to error and preserves the validator's explanation.
			recordSubcheckError(result, dnssecErr, "DNSSEC check error", "DNSSEC validation could not run")
		} else {
			result.Evidence = append(result.Evidence, dnssecResult.Evidence...)
			// Combine the verdicts explicitly: an unvalidated or failed
			// DNSSEC result is visible at its own severity — WARN
			// (indeterminate), FAIL (broken chain), or ERROR (validator
			// unavailable such as missing dig) — never reduced to PASS.
			if dnssecResult.Status != models.StatusPass && result.Status == models.StatusPass {
				result.Status = dnssecResult.Status
				result.Summary = fmt.Sprintf("%s; DNSSEC: %s", result.Summary, dnssecResult.Summary)
				if dnssecResult.Status == models.StatusFail {
					result.Violations = append(result.Violations, dnssecResult.Summary)
				}
			}
		}
	}

	return result, nil
}
