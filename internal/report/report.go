package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/velasco-jp/netaudit/internal/models"
)

// RenderJSON writes the report as JSON
func RenderJSON(w io.Writer, report *models.AuditReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// RenderHuman writes a human-friendly summary
func RenderHuman(w io.Writer, report *models.AuditReport) {
	statusLabel := strings.ToUpper(string(report.Status))
	fmt.Fprintf(w, "Audit: %s\n", report.Audit)
	fmt.Fprintf(w, "Status: %s\n\n", statusLabel)

	for _, f := range report.Findings {
		tag := statusTag(f.Status)
		fmt.Fprintf(w, "%s %s: %s\n", tag, f.CheckType, f.Summary)
		for _, v := range f.Violations {
			fmt.Fprintf(w, "       ↳ %s\n", v)
		}
	}

	fmt.Fprintf(w, "\nSummary: %d passed, %d failed, %d warnings, %d errors, %d skipped\n",
		report.Summary.Pass, report.Summary.Fail, report.Summary.Warn,
		report.Summary.Error, report.Summary.Skip)
}

// RenderResultJSON writes a single CheckResult as JSON
func RenderResultJSON(w io.Writer, result *models.CheckResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// RenderResultHuman writes a single CheckResult as human text
func RenderResultHuman(w io.Writer, result *models.CheckResult) {
	tag := statusTag(result.Status)
	fmt.Fprintf(w, "%s %s: %s\n", tag, result.CheckType, result.Summary)
	for _, v := range result.Violations {
		fmt.Fprintf(w, "       ↳ %s\n", v)
	}
	for _, e := range result.Evidence {
		fmt.Fprintf(w, "       • %s\n", e)
	}
}

func statusTag(s models.Status) string {
	switch s {
	case models.StatusPass:
		return "[PASS]"
	case models.StatusFail:
		return "[FAIL]"
	case models.StatusWarn:
		return "[WARN]"
	case models.StatusError:
		return "[ERR ]"
	case models.StatusSkip:
		return "[SKIP]"
	default:
		return "[????]"
	}
}
