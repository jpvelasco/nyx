package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/snapshot"
	"github.com/spf13/cobra"
)

var snapshotCmd = &cobra.Command{
	Use:   "snapshot",
	Short: "Manage audit history snapshots",
}

var snapshotBaselineCmd = &cobra.Command{
	Use:   "baseline [snapshot-file]",
	Short: "Set the current audit result as the baseline for long-term confidence",
	Long: `Capture the current audit as your "known good" baseline.

This is the foundation for sleeping well at night: future runs with 'nyx drift status'
will clearly show what has changed — new failures, degradations, or fixes — so you
always know if your segmentation and policies are still behaving as intended.

Run this right after a clean 'nyx audit --spec <your-spec>' when everything looks good.

You can also point it at a previously saved snapshot file to restore an older baseline:
  nyx snapshot baseline ~/.nyx/snapshots/snapshot-20250601-140000.json`,
	Args: cobra.MaximumNArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		var (
			specPath  string
			auditTime time.Time
			status    models.Status
			passed    int
			failed    int
			warned    int
			errored   int
		)

		if len(args) == 1 {
			// Restore baseline from a saved snapshot file
			snap, err := snapshot.LoadSnapshot(args[0])
			if err != nil {
				return fmt.Errorf("loading snapshot %s: %w", args[0], err)
			}
			if err := snapshot.SetBaseline(snap.SpecPath, &models.AuditReport{
				Runner:          snap.Runner,
				Summary:         snap.Summary,
				Status:          snap.Status,
				Findings:        snap.Findings,
				Recommendations: snap.Recommendations,
			}); err != nil {
				return fmt.Errorf("setting baseline: %w", err)
			}
			specPath = snap.SpecPath
			auditTime = snap.RunAt
			status = snap.Status
			passed = snap.Summary.Pass
			failed = snap.Summary.Fail
			warned = snap.Summary.Warn
			errored = snap.Summary.Error
		} else {
			if lastAuditReport == nil {
				return fmt.Errorf("no recent audit result — run 'nyx audit --spec <file>' first, then 'nyx snapshot baseline'")
			}
			if specFile == "" {
				return fmt.Errorf("no spec provided — use 'nyx audit --spec <file>' first")
			}

			if err := snapshot.SetBaseline(specFile, lastAuditReport); err != nil {
				return fmt.Errorf("setting baseline: %w", err)
			}

			specPath = specFile
			auditTime = time.Now()
			if len(lastAuditReport.Findings) > 0 {
				auditTime = lastAuditReport.Findings[0].StartedAt
			}
			status = lastAuditReport.Status
			passed = lastAuditReport.Summary.Pass
			failed = lastAuditReport.Summary.Fail
			warned = lastAuditReport.Summary.Warn
			errored = lastAuditReport.Summary.Error
		}

		fmt.Println("Baseline captured. Future drift checks will now show exactly what has changed.")
		fmt.Printf("  Spec:     %s\n", specPath)
		fmt.Printf("  Time:     %s\n", auditTime.Format(time.DateTime))
		fmt.Printf("  Status:   %s\n", status)
		fmt.Printf("  Passed:   %d\n", passed)
		fmt.Printf("  Failed:   %d\n", failed)
		fmt.Printf("  Warnings: %d\n", warned)
		fmt.Printf("  Errors:   %d\n", errored)
		fmt.Println("\nNext: run 'nyx audit' again later, then 'nyx drift status' to see what moved.")
		return nil
	},
}

var snapshotListCmd = &cobra.Command{
	Use:   "list",
	Short: "List saved snapshots",
	RunE: func(_ *cobra.Command, _ []string) error {
		snaps, err := snapshot.ListSnapshots()
		if err != nil {
			return err
		}

		if len(snaps) == 0 {
			fmt.Println("No snapshots found.")
			return nil
		}

		fmt.Printf("Saved snapshots (%d):\n", len(snaps))
		for _, s := range snaps {
			dir, _ := snapshot.Dir()
			if dir != "" {
				info, err := os.Stat(filepath.Join(dir, s))
				if err == nil {
					fmt.Printf("  %s  (captured %s)\n", s, info.ModTime().Format(time.DateTime))
				} else {
					fmt.Printf("  %s\n", s)
				}
			}
		}

		// Check baseline
		baselinePath := snapshot.BaselinePath()
		if info, err := os.Stat(baselinePath); err == nil {
			fmt.Printf("\nCurrent baseline: %s  (set %s)\n", filepath.Base(baselinePath), info.ModTime().Format(time.DateTime))
			fmt.Println("Use 'nyx drift status' after audits to see what has changed since then.")
		} else {
			fmt.Println("\nNo baseline set yet. Run 'nyx snapshot baseline' after a clean audit to start tracking drift.")
		}

		return nil
	},
}

var snapshotDeleteCmd = &cobra.Command{
	Use:   "delete [snapshot]",
	Short: "Delete a snapshot or all snapshots",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		if len(args) == 0 {
			// Delete all snapshots (not baseline)
			snaps, err := snapshot.ListSnapshots()
			if err != nil {
				return err
			}
			if len(snaps) == 0 {
				fmt.Println("No snapshots to delete.")
				return nil
			}
			dir, err := snapshot.Dir()
			if err != nil {
				return err
			}
			for _, s := range snaps {
				os.Remove(filepath.Join(dir, s))
			}
			fmt.Printf("Deleted %d snapshots.\n", len(snaps))
			return nil
		}

		// Delete specific snapshot
		snapName := args[0]
		dir, err := snapshot.Dir()
		if err != nil {
			return err
		}
		path := filepath.Join(dir, snapName)
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("deleting snapshot: %w", err)
		}
		fmt.Printf("Deleted snapshot %s.\n", snapName)
		return nil
	},
}

var snapshotClearBaselineCmd = &cobra.Command{
	Use:   "clear-baseline",
	Short: "Remove the baseline snapshot",
	RunE: func(_ *cobra.Command, _ []string) error {
		baselinePath := snapshot.BaselinePath()
		if baselinePath == "" {
			return fmt.Errorf("cannot determine baseline path")
		}
		if err := os.Remove(baselinePath); err != nil {
			if os.IsNotExist(err) {
				fmt.Println("No baseline to clear.")
				return nil
			}
			return fmt.Errorf("clearing baseline: %w", err)
		}
		fmt.Println("Baseline cleared.")
		return nil
	},
}

func init() {
	snapshotCmd.AddCommand(snapshotBaselineCmd)
	snapshotCmd.AddCommand(snapshotListCmd)
	snapshotCmd.AddCommand(snapshotDeleteCmd)
	snapshotCmd.AddCommand(snapshotClearBaselineCmd)
	rootCmd.AddCommand(snapshotCmd)
}
