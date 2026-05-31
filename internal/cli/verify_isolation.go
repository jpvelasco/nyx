package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/velasco-jp/nyx/internal/backends/system"
	"github.com/velasco-jp/nyx/internal/models"
	"github.com/velasco-jp/nyx/internal/report"
)

var (
	isolationFrom string
	isolationTo   string
)

var verifyIsolationCmd = &cobra.Command{
	Use:   "verify-isolation",
	Short: "Verify network isolation between zones",
	Example: `  nyx verify-isolation --from zone:clients --to 10.0.30.0/24
  nyx verify-isolation --from zone:clients --to zone:iot --json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if isolationTo == "" {
			return fmt.Errorf("--to is required")
		}

		dur, err := time.ParseDuration(timeout)
		if err != nil {
			dur = 60 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), dur)
		defer cancel()

		result := models.NewCheckResult("system", "isolation", "local", isolationTo)
		result.Observed["from"] = isolationFrom
		result.Observed["to"] = isolationTo

		// Try pinging the target to check reachability
		pingResult, err := system.Ping(ctx, isolationTo)
		if err != nil {
			result.Status = models.StatusWarn
			result.Summary = fmt.Sprintf("could not determine isolation: %v", err)
			result.Finish()
		} else {
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
		}

		w, err := getWriter()
		if err != nil {
			return err
		}
		if outputPath != "" {
			defer w.Close()
		}

		if jsonOutput {
			return report.RenderResultJSON(w, result)
		}
		report.RenderResultHuman(w, result)
		return nil
	},
}

func init() {
	verifyIsolationCmd.Flags().StringVar(&isolationFrom, "from", "", "Source zone or runner (e.g. zone:clients)")
	verifyIsolationCmd.Flags().StringVar(&isolationTo, "to", "", "Target zone, subnet, or IP")
}
