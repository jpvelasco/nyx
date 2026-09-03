package cli

import (
	"fmt"
	"time"

	"github.com/jpvelasco/nyx/internal/logger"
	"github.com/spf13/cobra"
)

var (
	logsSince   string
	logsLevel   string
	logsSubCmd  string
	logsLast    int
	logsFormat  string
	logsNoScrub bool
	logsOut     string
)

var logsParentCmd = &cobra.Command{
	Use:   "logs",
	Short: "Inspect nyx log output",
}

var logsExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export nyx log lines as a portable artifact (PII-scrubbed by default)",
	Long: `Export the nyx log rotation set (~/.nyx/nyx.log plus rotated generations)
as a single artifact you can attach to a bug report or hand to nyx
maintainers.

The artifact is PII-SCRUBBED BY DEFAULT: private IPs, hostnames, MAC
addresses, and token-like values are replaced with placeholders
([ip], [host], [mac], [redacted]), while every diagnostic field — event
names, HTTP method and REST path, retry timing, assertion outcomes,
error categories — survives. Use --no-scrub to get the raw, unredacted
lines; the command then prints a warning that the result may contain
PII.

Filters:
  --since  only entries from the last duration (e.g. 1h, 30m)
  --level  minimum level: debug (default), info, warn, error
  --cmd    only lines from one subsystem (audit, omada, opnsense, ...)
  --last   cap to the last N lines after filtering

Output:
  --format json (default, JSON-lines) or text (one human line per entry)
  -o file  write to a file (default: nyx-logs-<UTC>.log in the current
           directory; - for stdout)

The exporter only ever opens the log rotation set — never
credentials.json, its key file, or seen.json.`,
	RunE: func(_ *cobra.Command, _ []string) error {
		srcPath := logger.EnvLogFile()
		entries, err := logger.ReadRotation(srcPath)
		if err != nil {
			return fmt.Errorf("reading logs from %s: %w", srcPath, err)
		}
		minLevel, err := logger.ParseLevelFlag(logsLevel)
		if err != nil {
			return err
		}
		switch logsFormat {
		case "json", "text":
		default:
			return fmt.Errorf("invalid --format %q: expected json or text", logsFormat)
		}
		var sinceDur time.Duration
		if logsSince != "" { // empty = no time filter
			sinceDur, err = time.ParseDuration(logsSince)
			if err != nil {
				return fmt.Errorf("invalid --since %q: expected a duration like 30m or 1h: %v", logsSince, err)
			}
		}
		entries = logger.FilterEntries(entries, logger.ExportFilters{
			Since: sinceDur,
			Level: minLevel,
			Cmd:   logsSubCmd,
			Last:  logsLast,
		})
		out := logsOut
		if out == "" {
			out = fmt.Sprintf("nyx-logs-%s.log", time.Now().UTC().Format("20060102-150405"))
		}
		if _, err := logger.WriteArtifact(entries, srcPath, logger.ExportOptions{
			Format: logsFormat,
			Scrub:  !logsNoScrub,
			Out:    out,
		}); err != nil {
			return err
		}
		if out != "-" {
			fmt.Printf("wrote log artifact to %s\n", out)
		}
		return nil
	},
}

func init() {
	logsExportCmd.Flags().StringVar(&logsSince, "since", "", "Only entries from the last duration (e.g. 30m, 1h)")
	logsExportCmd.Flags().StringVar(&logsLevel, "level", "debug", "Minimum level: debug, info, warn, error")
	logsExportCmd.Flags().StringVar(&logsSubCmd, "cmd", "", "Only entries from one subsystem (audit, omada, opnsense, ...)")
	logsExportCmd.Flags().IntVar(&logsLast, "last", 0, "Cap to the last N lines after filtering")
	logsExportCmd.Flags().StringVar(&logsFormat, "format", "json", "Output format: json (JSON-lines) or text")
	logsExportCmd.Flags().BoolVar(&logsNoScrub, "no-scrub", false, "Emit raw, unredacted lines (not safe to share)")
	logsExportCmd.Flags().StringVarP(&logsOut, "out", "o", "", "Output file (default: nyx-logs-<UTC>.log in the current directory; - for stdout)")
	logsParentCmd.AddCommand(logsExportCmd)
}
