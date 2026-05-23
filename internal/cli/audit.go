package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/velasco-jp/nyx/internal/audit"
	"github.com/velasco-jp/nyx/internal/intent"
	"github.com/velasco-jp/nyx/internal/models"
	"github.com/velasco-jp/nyx/internal/recommendations"
	"github.com/velasco-jp/nyx/internal/report"
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Run a full audit from a YAML spec",
	Example: `  nyx audit --spec homelab.yaml
  nyx audit --spec homelab.yaml --json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if specFile == "" {
			return fmt.Errorf("--spec is required")
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
		auditReport, err := engine.Run(ctx)
		if err != nil {
			return fmt.Errorf("audit failed: %w", err)
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

		// Generate and render recommendations for non-pass, non-error states
		if auditReport.Status != models.StatusPass && auditReport.Status != models.StatusError {
			var failures []models.CheckResult
			for _, f := range auditReport.Findings {
				if f.Status != models.StatusPass && f.Status != models.StatusSkip {
					failures = append(failures, f)
				}
			}
			networks := make(map[string]*intent.Network)
			for i := range spec.Networks {
				n := &spec.Networks[i]
				networks[n.Name] = n
			}
			recs, recErr := recommendations.GenerateRecommendations(failures, networks)
			if recErr == nil && len(recs) > 0 {
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

		return nil
	},
}
