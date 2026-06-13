// Package cli implements all Cobra commands and the top-level Execute entrypoint for the nyx binary.
package cli

import (
	"fmt"
	"os"

	"github.com/jpvelasco/nyx/internal/logger"
	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/version"
	"github.com/spf13/cobra"
)

var (
	jsonOutput          bool
	outputPath          string
	specFile            string
	verbose             bool
	timeout             string
	interfaceOpt        string
	warnVirtual         bool
	skipHostKeyVerify   bool
	log                 *logger.Logger

	// lastAuditReport caches the most recent audit result so that
	// `nyx snapshot baseline` and `nyx drift status` can work immediately after an audit.
	lastAuditReport *models.AuditReport
)

var rootCmd = &cobra.Command{
	Use:   "nyx",
	Short: "Validate private network behavior against intended state",
	Long: `nyx is an open-source CLI for validating private internal networks
against intended behavior. It combines live checks, declared intent via YAML
specs, and agent-friendly output for homelabs and developer environments.`,
	SilenceUsage: true,
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output results as JSON")
	rootCmd.PersistentFlags().StringVar(&outputPath, "output", "", "Write output to file")
	rootCmd.PersistentFlags().StringVar(&specFile, "spec", "", "Path to YAML spec file")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "Enable verbose output")
	rootCmd.PersistentFlags().StringVar(&timeout, "timeout", "60s", "Timeout for operations")
	rootCmd.PersistentFlags().StringVar(&interfaceOpt, "interface", "", "Network interface to use for local checks (e.g. \"Ethernet\", \"Wi-Fi\"). Leave empty for automatic selection.")
	auditCmd.Flags().BoolVar(&warnVirtual, "warn-virtual", false, "Always warn on virtual subnets, even if previously acknowledged")
	auditCmd.Flags().BoolVar(&skipHostKeyVerify, "skip-host-key-verify", false, "Skip SSH host key verification for probes (like ssh -o StrictHostKeyChecking=no)")

	rootCmd.AddCommand(discoverCmd)
	rootCmd.AddCommand(checkRoutesCmd)
	rootCmd.AddCommand(checkVPNCmd)
	rootCmd.AddCommand(verifyIsolationCmd)
	rootCmd.AddCommand(auditCmd)
	rootCmd.AddCommand(mcpCmd)
	rootCmd.AddCommand(providerCmd)
	rootCmd.AddCommand(versionCmd)

	// Logger is best-effort — if it fails, we continue without logging.
	if l, err := logger.New(logger.DefaultPath(), 5*1024*1024, 3); err == nil {
		log = l
	}
}

// Execute sets up provider subcommands and runs the root Cobra command. Returns error for os.Exit(2).
func Execute() error {
	BuildProviderSubcommands(rootCmd)
	return rootCmd.Execute()
}

func getWriter() (*os.File, error) {
	if outputPath != "" {
		// #nosec G304 — path from CLI flag
		f, err := os.OpenFile(outputPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600) // nosemgrep
		if err != nil {
			return nil, fmt.Errorf("opening output file %q: %w", outputPath, err)
		}
		return f, nil
	}
	return os.Stdout, nil
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Printf("nyx v%s\n", version.Version)
	},
}

// GetSelectedInterface returns the user-specified interface name (if any).
// Empty string means "auto".
func GetSelectedInterface() string {
	return interfaceOpt
}
