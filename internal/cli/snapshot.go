package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
	"github.com/velasco-jp/nyx/internal/snapshot"
)

var snapshotCmd = &cobra.Command{
	Use:   "snapshot",
	Short: "Manage audit history snapshots",
}

var snapshotBaselineCmd = &cobra.Command{
	Use:   "baseline",
	Short: "Set the current audit result as the baseline for long-term confidence",
	Long: `Capture the current audit as your "known good" baseline.

This is the foundation for sleeping well at night: future runs with 'nyx drift status'
will clearly show what has changed — new failures, degradations, or fixes — so you
always know if your segmentation and policies are still behaving as intended.

Run this right after a clean 'nyx audit --spec <your-spec>' when everything looks good.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if lastAuditReport == nil {
			return fmt.Errorf("no recent audit result — run 'nyx audit --spec <file>' first, then 'nyx snapshot baseline'")
		}
		if specFile == "" {
			return fmt.Errorf("no spec provided — use 'nyx audit --spec <file>' first")
		}

		if err := snapshot.SetBaseline(specFile, lastAuditReport); err != nil {
			return fmt.Errorf("setting baseline: %w", err)
		}

		// Safely extract a timestamp (avoid panic if Findings is unexpectedly empty)
		auditTime := time.Now()
		if len(lastAuditReport.Findings) > 0 {
			auditTime = lastAuditReport.Findings[0].StartedAt
		}

		fmt.Println("Baseline captured. Future drift checks will now show exactly what has changed.")
		fmt.Printf("  Time:     %s\n", auditTime.Format(time.DateTime))
		fmt.Printf("  Status:   %s\n", lastAuditReport.Status)
		fmt.Printf("  Passed:   %d\n", lastAuditReport.Summary.Pass)
		fmt.Printf("  Failed:   %d\n", lastAuditReport.Summary.Fail)
		fmt.Printf("  Warnings: %d\n", lastAuditReport.Summary.Warn)
		fmt.Printf("  Errors:   %d\n", lastAuditReport.Summary.Error)
		fmt.Println("\nNext: run 'nyx audit' again later, then 'nyx drift status' to see what moved.")
		return nil
	},
}

var snapshotListCmd = &cobra.Command{
	Use:   "list",
	Short: "List saved snapshots",
	RunE: func(cmd *cobra.Command, args []string) error {
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
			dir, _ := snapshot.SnapshotDir()
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
	RunE: func(cmd *cobra.Command, args []string) error {
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
			dir, err := snapshot.SnapshotDir()
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
		dir, err := snapshot.SnapshotDir()
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
	RunE: func(cmd *cobra.Command, args []string) error {
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
