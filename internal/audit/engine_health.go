package audit

import (
	"context"
	"fmt"

	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
)

func (e *Engine) runNetworkHealth(ctx context.Context, a intent.Assertion) (*models.CheckResult, error) {
	var result *models.CheckResult
	var err error

	if a.ExpectLatencyMs > 0 || a.ExpectLossPct > 0 {
		result, err = e.Backend.CheckLatencyAndLoss(ctx, a.Target, a.ExpectLatencyMs, a.ExpectLossPct)
	} else {
		result, _, err = e.Backend.PingCheck(ctx, a.Target, 10)
	}
	if err != nil {
		return nil, fmt.Errorf("network health check failed: %w", err)
	}

	if a.ExpectMTU > 0 {
		mtuResult, mtuErr := e.Backend.ProbeMTU(ctx, a.Target, a.ExpectMTU)
		if mtuErr != nil {
			// The declared MTU expectation could not be measured at all.
			// An unevaluated expectation must not read as a passing
			// health assertion: the finding escalates to error,
			// mirroring the local DNSSEC error handling (#270).
			recordSubcheckError(result, mtuErr, "MTU probe error", "MTU measurement could not run")
		} else {
			result.Evidence = append(result.Evidence, mtuResult.Evidence...)
			switch {
			case mtuResult.Status == models.StatusFail && result.Status == models.StatusPass:
				result.Status = models.StatusFail
				result.Violations = append(result.Violations, mtuResult.Summary)
			case mtuResult.Status == models.StatusWarn && result.Status == models.StatusPass:
				result.Status = models.StatusWarn
			case mtuResult.Status == models.StatusError && result.Status == models.StatusPass:
				// An unmeasurable MTU (no probe size confirmed) must not
				// read as a passing health assertion.
				result.Status = models.StatusError
				result.Violations = append(result.Violations, mtuResult.Summary)
			}
			if mtu, ok := mtuResult.Observed["mtu"]; ok {
				result.Observed["mtu"] = mtu
			}
		}
	}

	return result, nil
}
