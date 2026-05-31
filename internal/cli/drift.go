package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/velasco-jp/nyx/internal/models"
	"github.com/velasco-jp/nyx/internal/snapshot"
)

var driftCmd = &cobra.Command{
	Use:   "drift",
	Short: "Detect drift in network audit results",
}

var driftStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "See exactly what has changed since your last known-good baseline",
	Long: `Compare the latest audit against the baseline you set with 'nyx snapshot baseline'.

This is the tool that lets you sleep at night: it surfaces new failures, degradations,
fixes, and warnings in clear language so you know immediately if your network intent
is still holding or if something needs attention.

Run after any 'nyx audit' (especially from different VLANs or after changes). If no
fresh audit is available, falls back to the most recent saved snapshot.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		baseline, err := snapshot.LoadBaseline()
		if err != nil {
			return err
		}

		var current *snapshot.Snapshot
		if lastAuditReport != nil {
			current = snapshot.NewSnapshot(specFile, lastAuditReport)
		} else {
			// Fallback: load the most recent saved snapshot
			var snaps []string
			snaps, err = snapshot.ListSnapshots()
			if err != nil {
				return fmt.Errorf("listing snapshots: %w", err)
			}
			if len(snaps) == 0 {
				return fmt.Errorf("no recent audit result and no saved snapshots — run 'nyx audit --spec <file>' first")
			}
			dir, err := snapshot.SnapshotDir()
			if err != nil {
				return err
			}
			current, err = snapshot.LoadSnapshot(filepath.Join(dir, snaps[len(snaps)-1]))
			if err != nil {
				return fmt.Errorf("loading most recent snapshot: %w", err)
			}
		}

		drift := snapshot.ComputeDrift(baseline, current)

		renderDrift(drift)

		// Set exit code based on drift (fail on new problems or regression to error state)
		if len(drift.NewFailures) > 0 || len(drift.Degraded) > 0 ||
			(drift.CurrentStatus == models.StatusError && drift.BaselineStatus != models.StatusError) {
			os.Exit(1)
		}
		return nil
	},
}

var driftCompareCmd = &cobra.Command{
	Use:   "compare [snapshot1] [snapshot2]",
	Short: "Compare two snapshots",
	Args:  cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := snapshot.SnapshotDir()
		if err != nil {
			return err
		}

		baseline, err := snapshot.LoadSnapshot(filepath.Join(dir, args[0]))
		if err != nil {
			return fmt.Errorf("loading baseline snapshot %s: %w", args[0], err)
		}

		current, err := snapshot.LoadSnapshot(filepath.Join(dir, args[1]))
		if err != nil {
			return fmt.Errorf("loading current snapshot %s: %w", args[1], err)
		}

		drift := snapshot.ComputeDrift(baseline, current)
		renderDrift(drift)
		return nil
	},
}

func renderDrift(drift *snapshot.DriftResult) {
	fmt.Println("=== Drift Report ===")
	fmt.Printf("Baseline: %s (status: %s)\n", drift.BaselineTime.Format(time.DateTime), drift.BaselineStatus)
	fmt.Printf("Current:  %s (status: %s)\n", drift.CurrentTime.Format(time.DateTime), drift.CurrentStatus)
	fmt.Printf("Change:   %s\n", drift.Summary.NetChange)
	fmt.Println()

	// Summary
	fmt.Println("Summary:")
	fmt.Printf("  Baseline: %d passed, %d failed, %d warnings, %d errors\n",
		drift.Summary.BaselinePass, drift.Summary.BaselineFail,
		drift.Summary.BaselineWarn, drift.Summary.BaselineError)
	fmt.Printf("  Current:  %d passed, %d failed, %d warnings, %d errors\n",
		drift.Summary.CurrentPass, drift.Summary.CurrentFail,
		drift.Summary.CurrentWarn, drift.Summary.CurrentError)
	fmt.Printf("  Net:      %s\n", drift.Summary.NetChange)
	fmt.Println()

	// New failures — these are the things that should keep you up at night
	if len(drift.NewFailures) > 0 {
		fmt.Printf("New failures (%d) — attention needed:\n", len(drift.NewFailures))
		for _, f := range drift.NewFailures {
			fmt.Printf("  %s %s: %s\n", statusTag(f.Status), f.CheckType, f.Summary)
		}
		fmt.Println()
	}

	// Degraded — things that were worse before but got worse again
	if len(drift.Degraded) > 0 {
		fmt.Printf("Degraded (%d) — was okay, now worse:\n", len(drift.Degraded))
		for _, f := range drift.Degraded {
			fmt.Printf("  %s %s: %s\n", statusTag(f.Status), f.CheckType, f.Summary)
		}
		fmt.Println()
	}

	// Fixed failures — good news
	if len(drift.FixedFailures) > 0 {
		fmt.Printf("Fixed (%d) — good news:\n", len(drift.FixedFailures))
		for _, f := range drift.FixedFailures {
			fmt.Printf("  %s %s: %s\n", statusTag(f.Status), f.CheckType, f.Summary)
		}
		fmt.Println()
	}

	// Improved — also good news
	if len(drift.Improved) > 0 {
		fmt.Printf("Improved (%d) — getting better:\n", len(drift.Improved))
		for _, f := range drift.Improved {
			fmt.Printf("  %s %s: %s\n", statusTag(f.Status), f.CheckType, f.Summary)
		}
		fmt.Println()
	}

	// New warnings — worth watching but not urgent
	if len(drift.NewWarnings) > 0 {
		fmt.Printf("New warnings (%d) — worth watching:\n", len(drift.NewWarnings))
		for _, f := range drift.NewWarnings {
			fmt.Printf("  %s %s: %s\n", statusTag(f.Status), f.CheckType, f.Summary)
		}
		fmt.Println()
	}

	// No drift — the best outcome
	if len(drift.NewFailures) == 0 && len(drift.Degraded) == 0 &&
		len(drift.FixedFailures) == 0 && len(drift.NewWarnings) == 0 {
		fmt.Println("All good — no drift since the baseline. Your network is behaving as intended.")
		fmt.Println("Run 'nyx snapshot baseline' again after intentional changes to update your reference point.")
	} else {
		fmt.Println("Next: investigate the checks that changed. Re-audit from other VLANs with --interface if the vantage point matters.")
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

func init() {
	driftCmd.AddCommand(driftStatusCmd)
	driftCmd.AddCommand(driftCompareCmd)
	rootCmd.AddCommand(driftCmd)
}
