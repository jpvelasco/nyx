package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/velasco-jp/nyx/internal/audit"
	"github.com/velasco-jp/nyx/internal/intent"
	"github.com/velasco-jp/nyx/internal/models"
	"github.com/velasco-jp/nyx/internal/recommendations"
	"github.com/velasco-jp/nyx/internal/report"
	"github.com/velasco-jp/nyx/internal/snapshot"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Run a full audit from a YAML spec",
	Example: `  nyx audit --spec homelab.yaml
  nyx audit --spec homelab.yaml --json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if specFile == "" {
			// First Contact mode: orient the user immediately
			brief := GetEnvironmentBriefing(nil)
			fmt.Println(RenderEnvironmentBriefing(brief))
			fmt.Println("No spec provided. Here's what you can do next:")
			fmt.Println("  nyx doctor              — full environment health check")
			fmt.Println("  nyx init                — generate a starter spec from what I see")
			fmt.Println("  nyx audit --spec <file> — run a full audit against your spec")
			return nil
		}

		spec, err := intent.LoadSpec(specFile)
		if err != nil {
			return fmt.Errorf("loading spec: %w", err)
		}

		dur, parseErr := time.ParseDuration(timeout)
		if parseErr != nil {
			dur = 300 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), dur)
		defer cancel()

		engine := audit.NewEngine(spec)
		engine.Interface = GetSelectedInterface()
		engine.WarnVirtual = warnVirtual
		auditReport, err := engine.Run(ctx)
		if err != nil {
			return fmt.Errorf("audit failed: %w", err)
		}

		// Cache the report for snapshot/drift commands
		lastAuditReport = auditReport

		// Save snapshot
		if snapPath, snapErr := snapshot.Save(specFile, auditReport); snapErr == nil {
			if log != nil {
				log.Info("snapshot", map[string]interface{}{
					"path": snapPath,
				})
			}
		}

		if log != nil {
			log.Info("audit", map[string]interface{}{
				"status":          string(auditReport.Status),
				"assertion_count": len(auditReport.Findings),
				"pass":            auditReport.Summary.Pass,
				"fail":            auditReport.Summary.Fail,
				"warn":            auditReport.Summary.Warn,
				"error":           auditReport.Summary.Error,
			})
		}

		w, err := getWriter()
		if err != nil {
			return err
		}
		if outputPath != "" {
			defer w.Close()
		}

		if jsonOutput {
			return report.RenderJSON(w, auditReport)
		}
		report.RenderHuman(w, auditReport)

		// Generate and render recommendations for actionable findings.
		// We include Fail, Warn, *and* Error results for network-behavior checks.
		// Timeouts and "unreachable from here" errors are some of the most common
		// real-world signals (especially when scanning from the wrong VLAN).
		// Pure setup/auth errors (e.g. missing Omada credentials) are deliberately skipped.
		var failures []models.CheckResult
		seen := make(map[int]bool)
		for i, f := range auditReport.Findings {
			include := f.Status == models.StatusFail || f.Status == models.StatusWarn || f.Status == models.StatusError

			if include {
				// Skip pure configuration / credential errors — these are not
				// network behavior problems the user can fix via probes or routing.
				if f.CheckType == "acl_check" && strings.Contains(f.Summary, "requires") {
					include = false
				}
			}

			if include {
				if !seen[i] {
					failures = append(failures, f)
					seen[i] = true
				}
			}
		}

		if len(failures) > 0 {
			recs, recErr := recommendations.GenerateRecommendations(failures, spec, auditReport.Runner)
			if recErr == nil && len(recs) > 0 {
				// Convert recommendations to models.Recommendation for JSON output
				var modelRecs []models.Recommendation
				for _, r := range recs {
					modelRecs = append(modelRecs, models.Recommendation{
						Priority:    r.Priority,
						Category:    r.Category,
						Title:       r.Title,
						Description: r.Description,
						Remediation: r.Remediation,
						Affected:    r.Affected,
						SpecPatch:   r.SpecPatch,
					})
				}
				auditReport.Recommendations = modelRecs
				report.RenderRecommendations(w, recs)
			}
		}

		// Set exit code based on audit status
		switch auditReport.Status {
		case models.StatusFail:
			os.Exit(1)
		case models.StatusError:
			os.Exit(2)
		case models.StatusWarn:
			os.Exit(3)
		}

		// Long-term value encouragement (helps users build the "sleep at night" habit)
		if specFile != "" {
			fmt.Fprintln(w, "\nFor history, trend analysis, and drift detection over time:")
			fmt.Fprintln(w, "  nyx snapshot baseline   # capture this run as your baseline")
			fmt.Fprintln(w, "  nyx drift status        # compare future runs against it")
		}

		return nil
	},
}
