package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/velasco-jp/nyx/internal/logger"
	"github.com/velasco-jp/nyx/internal/models"
	"github.com/velasco-jp/nyx/internal/version"
)

var (
	jsonOutput      bool
	outputPath      string
	specFile        string
	verbose         bool
	timeout         string
	interfaceOpt    string // user-specified interface/NIC for local runs
	log             *logger.Logger
	lastAuditReport *models.AuditReport // cached for snapshot/drift commands
)

var rootCmd = &cobra.Command{
	Use:   "nyx",
	Short: "Validate private network behavior against intended state",
	Long: `nyx is an open-source CLI for validating private internal networks
against intended behavior. It combines live checks, declared intent via YAML
specs, and agent-friendly output for homelabs and developer environments.`,
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// First run: orient the user and tell them what to do
		brief := GetEnvironmentBriefing(nil)
		fmt.Println("nyx — network validation that tells you what's wrong and how to fix it.")
		fmt.Println()
		fmt.Println(RenderEnvironmentBriefing(brief))
		fmt.Println("Quick start:")
		fmt.Println("  nyx doctor              — check if your environment is ready")
		fmt.Println("  nyx init                — auto-generate a starter spec from your network")
		fmt.Println("  nyx audit --spec <file> — run a full audit against your intent")
		fmt.Println()
		fmt.Println("Run nyx <command> --help for details on any command.")
		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "Output results as JSON")
	rootCmd.PersistentFlags().StringVar(&outputPath, "output", "", "Write output to file")
	rootCmd.PersistentFlags().StringVar(&specFile, "spec", "", "Path to YAML spec file")
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "Enable verbose output")
	rootCmd.PersistentFlags().StringVar(&timeout, "timeout", "60s", "Timeout for operations")
	rootCmd.PersistentFlags().StringVar(&interfaceOpt, "interface", "", "Network interface to use for local checks (e.g. \"Ethernet\", \"Wi-Fi\"). Leave empty for automatic selection.")

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

func Execute() error {
	BuildProviderSubcommands(rootCmd)
	return rootCmd.Execute()
}

func getWriter() (*os.File, error) {
	if outputPath != "" {
		f, err := os.Create(outputPath)
		if err != nil {
			return nil, fmt.Errorf("opening output file %q: %w", outputPath, err)
		}
		return f, nil
	}
	return os.Stdout, nil
}

// GetSelectedInterface returns the user-specified interface name (if any).
// Empty string means "auto".
func GetSelectedInterface() string {
	return interfaceOpt
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("nyx v%s\n", version.Version)
	},
}
