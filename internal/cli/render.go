package cli

import (
	"os"

	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/report"
)

// renderCheckResult renders a single check result in the selected output
// format (JSON or human) and maps its status to the process exit code, so
// every output path honors the 0/1/2/3 contract.
func renderCheckResult(w *os.File, result *models.CheckResult) error {
	if jsonOutput {
		if err := report.RenderResultJSON(w, result); err != nil {
			return err
		}
		return statusExitError(result.Status)
	}
	report.RenderResultHuman(w, result)
	return statusExitError(result.Status)
}

// renderAuditReport renders an audit report as JSON and maps its status to
// the process exit code. Used where only the JSON path is offered (doctor,
// audit --json).
func renderAuditReport(w *os.File, r *models.AuditReport) error {
	if err := report.RenderJSON(w, r); err != nil {
		return err
	}
	return statusExitError(r.Status)
}
