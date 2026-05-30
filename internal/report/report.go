package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/velasco-jp/nyx/internal/models"
	"github.com/velasco-jp/nyx/internal/recommendations"
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
	fmt.Fprintf(w, "Site: %s\n", report.Audit)
	fmt.Fprintf(w, "Status: %s\n", statusLabel)

	// First Contact: orient the user before showing results
	if len(report.Runner.LocalIPs) > 0 {
		fmt.Fprintf(w, "Running from: %s", strings.Join(report.Runner.LocalIPs, ", "))
		if len(report.Runner.Networks) > 0 {
			fmt.Fprintf(w, " (inside: %s)", strings.Join(report.Runner.Networks, ", "))
		} else {
			fmt.Fprintf(w, " (outside any spec network — checks may be from the wrong vantage point)")
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w)
		fmt.Fprintf(w, "--- %d assertions, evaluated from this vantage point ---\n", len(report.Findings))
	}

	for _, f := range report.Findings {
		tag := statusTag(f.Status)
		fmt.Fprintf(w, "%s %s: %s\n", tag, f.CheckType, f.Summary)
		for _, v := range f.Violations {
			fmt.Fprintf(w, "       ↳ %s\n", v)
		}
		for _, e := range f.Evidence {
			printEvidence(w, e)
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
		printEvidence(w, e)
	}
}

// printEvidence prints an evidence string, splitting multi-line blobs into
// individual indented lines so raw nmap output and route tables are readable.
func printEvidence(w io.Writer, e string) {
	lines := strings.Split(strings.ReplaceAll(e, "\r\n", "\n"), "\n")
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		fmt.Fprintf(w, "       • %s\n", line)
	}
}

// RenderRecommendations writes the recommendations block to w
func RenderRecommendations(w io.Writer, recs []recommendations.Recommendation) {
	if len(recs) == 0 {
		return
	}
	fmt.Fprintln(w, "\n--- What's Likely Going Wrong ---")
	for _, r := range recs {
		fmt.Fprintf(w, "  [%d] %s (%s)\n", r.Priority, r.Title, r.Category)
		fmt.Fprintf(w, "      %s\n", r.Description)
		fmt.Fprintf(w, "      Fix: %s\n", r.Remediation)

		if len(r.Affected) > 0 {
			if len(r.Affected) == 1 {
				fmt.Fprintf(w, "      Affected: %s\n", r.Affected[0])
			} else if len(r.Affected) <= 4 {
				fmt.Fprintf(w, "      Affected (%d): %s\n", len(r.Affected), strings.Join(r.Affected, ", "))
			} else {
				fmt.Fprintf(w, "      Affected (%d checks):\n", len(r.Affected))
				for _, a := range r.Affected {
					fmt.Fprintf(w, "        • %s\n", a)
				}
			}
		}

		if r.SpecPatch != "" {
			fmt.Fprintln(w, "      Suggested spec addition:")
			for _, line := range strings.Split(r.SpecPatch, "\n") {
				if line != "" {
					fmt.Fprintf(w, "        %s\n", line)
				}
			}
		}

		fmt.Fprintln(w)
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
