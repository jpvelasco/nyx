package cli

import (
	"context"
	"fmt"

	"github.com/jpvelasco/nyx/internal/audit"
	"github.com/jpvelasco/nyx/internal/backends/system"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	"github.com/spf13/cobra"
)

var (
	isolationFrom string
	isolationTo   string
)

var verifyIsolationCmd = &cobra.Command{
	Use:   "verify-isolation",
	Short: "Verify network isolation between zones",
	Example: `  nyx verify-isolation --from zone:clients --to 10.0.30.0/24
  nyx verify-isolation --from zone:clients --to zone:iot --json
  nyx verify-isolation --from zone:clients --to zone:iot --spec homelab.yaml`,
	RunE: func(_ *cobra.Command, _ []string) error {
		if isolationTo == "" {
			return fmt.Errorf("--to is required")
		}

		dur, err := parseTimeoutFlag(timeout)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), dur)
		defer cancel()

		var result *models.CheckResult
		if specFile != "" {
			// With a spec, --from is honored end to end: the isolation
			// assertion runs through the engine, which resolves --from to a
			// declared zone and only issues a definitive verdict when this
			// host is inside that zone (same semantics as `nyx audit`).
			result, err = verifyIsolationViaEngine(ctx)
			if err != nil {
				return err
			}
		} else {
			// Without a spec there is no zone mapping, so --from is a label
			// and the check pings --to directly from this host.
			result = verifyIsolationViaPing(ctx)
		}

		w, err := getWriter()
		if err != nil {
			return err
		}
		if outputPath != "" {
			defer w.Close()
		}

		return renderCheckResult(w, result)
	},
}

// verifyIsolationViaEngine evaluates an isolation assertion from the declared
// spec. The engine resolves both zones and derives the runner context, so the
// verdict is definitive only when this host sits inside the --from zone.
func verifyIsolationViaEngine(ctx context.Context) (*models.CheckResult, error) {
	if isolationFrom == "" {
		return nil, fmt.Errorf("--from is required when --spec is provided (it is resolved as a zone or network in the spec)")
	}
	spec, err := intent.LoadSpec(specFile)
	if err != nil {
		return nil, fmt.Errorf("loading spec %s: %w", specFile, err)
	}
	if !specResolvesZone(spec, isolationFrom) {
		return nil, fmt.Errorf("source zone %q is not declared in %s — add a network with zone or name %q to the spec", isolationFrom, specFile, isolationFrom)
	}

	miniSpec := &intent.Spec{
		Version:  spec.Version,
		Site:     spec.Site,
		Networks: spec.Networks,
		Assertions: []intent.Assertion{{
			Type:   "isolation",
			From:   isolationFrom,
			To:     isolationTo,
			Expect: "deny",
		}},
	}
	eng := audit.NewEngine(miniSpec)
	eng.Interface = GetSelectedInterface()
	eng.SkipHostKeyVerify = skipHostKeyVerify

	report, err := eng.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("isolation check failed: %w", err)
	}
	if len(report.Findings) == 0 {
		return nil, fmt.Errorf("no findings returned for isolation check")
	}
	result := report.Findings[0]
	return &result, nil
}

// specResolvesZone reports whether the spec declares the value as a zone or a
// network name.
func specResolvesZone(spec *intent.Spec, zone string) bool {
	return len(spec.NetworkByZone(zone)) > 0 || spec.NetworkByName(zone) != nil
}

// verifyIsolationViaPing pings --to directly from this host. The --from value
// is carried as a label only; there is no zone mapping without a spec.
func verifyIsolationViaPing(ctx context.Context) *models.CheckResult {
	result := models.NewCheckResult("system", "isolation", "local", isolationTo)
	result.Observed["from"] = isolationFrom
	result.Observed["to"] = isolationTo

	pingResult, err := system.Ping(ctx, isolationTo)
	if err != nil {
		result.Status = models.StatusWarn
		result.Summary = fmt.Sprintf("could not determine isolation: %v", err)
		result.Finish()
		return result
	}

	result.Observed["reachable"] = pingResult.Reachable
	if pingResult.Reachable {
		result.Status = models.StatusFail
		result.Summary = fmt.Sprintf("isolation VIOLATED: %s can reach %s", isolationFrom, isolationTo)
		result.Violations = append(result.Violations, "target is reachable when isolation is expected")
	} else {
		result.Status = models.StatusPass
		result.Summary = fmt.Sprintf("isolation confirmed: %s cannot reach %s", isolationFrom, isolationTo)
	}
	result.Finish()
	return result
}

func init() {
	verifyIsolationCmd.Flags().StringVar(&isolationFrom, "from", "", "Source zone or network (e.g. zone:clients); resolved against the spec when --spec is provided")
	verifyIsolationCmd.Flags().StringVar(&isolationTo, "to", "", "Target zone, subnet, or IP")
}
