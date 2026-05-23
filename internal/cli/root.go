package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/velasco-jp/nyx/internal/version"
)

var (
	jsonOutput bool
	outputPath string
	specFile   string
	verbose    bool
	timeout    string
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

	rootCmd.AddCommand(discoverCmd)
	rootCmd.AddCommand(checkRoutesCmd)
	rootCmd.AddCommand(checkVPNCmd)
	rootCmd.AddCommand(verifyIsolationCmd)
	rootCmd.AddCommand(auditCmd)
	rootCmd.AddCommand(mcpCmd)
	rootCmd.AddCommand(omadaCmd)
	rootCmd.AddCommand(versionCmd)
}

func Execute() error {
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

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("nyx v%s\n", version.Version)
	},
}
