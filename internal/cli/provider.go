package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	providers "github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/report"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	providerHost     string
	providerUsername string
	providerPassword string
	providerSite     string
	providerDebug    bool
	providerOutFile  string
)

var providerCmd = &cobra.Command{
	Use:   "provider",
	Short: "Manage and query registered network providers",
}

var providerListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all registered providers and their capabilities",
	RunE: func(_ *cobra.Command, _ []string) error {
		list := providers.List()
		sort.Slice(list, func(i, j int) bool {
			return list[i].Name() < list[j].Name()
		})
		if jsonOutput {
			type entry struct {
				Name         string   `json:"name"`
				Capabilities []string `json:"capabilities"`
			}
			out := make([]entry, len(list))
			for i, p := range list {
				out[i] = entry{Name: p.Name(), Capabilities: p.Capabilities()}
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(out)
		}
		if len(list) == 0 {
			fmt.Println("No providers registered.")
			return nil
		}
		fmt.Printf("%-15s %s\n", "PROVIDER", "CAPABILITIES")
		for _, p := range list {
			caps := ""
			for i, c := range p.Capabilities() {
				if i > 0 {
					caps += ", "
				}
				caps += c
			}
			fmt.Printf("%-15s %s\n", p.Name(), caps)
		}
		return nil
	},
}

// BuildProviderSubcommands creates `nyx <vendor> import/check/info` subcommands
// for each registered provider and adds them to root.
func BuildProviderSubcommands(root *cobra.Command) {
	for _, p := range providers.List() {
		p := p
		vendorCmd := &cobra.Command{
			Use:   p.Name(),
			Short: fmt.Sprintf("%s provider commands", p.Name()),
		}

		caps := map[string]bool{}
		for _, c := range p.Capabilities() {
			caps[c] = true
		}

		if caps["info"] {
			vendorCmd.AddCommand(buildInfoCmd(p))
		}
		if caps["import"] {
			vendorCmd.AddCommand(buildImportCmd(p))
		}
		if caps["check"] {
			vendorCmd.AddCommand(buildCheckCmd(p))
		}

		root.AddCommand(vendorCmd)
	}
}

func buildInfoCmd(p providers.Provider) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "info",
		Short: fmt.Sprintf("Show %s controller version and connection info", p.Name()),
		RunE: func(_ *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			info, err := p.Info(ctx, providers.ImportOptions{
				Host:     providerHost,
				Username: providerUsername,
				Password: providerPassword,
			})
			if err != nil {
				return err
			}
			if jsonOutput {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(info)
			}
			fmt.Printf("Provider : %s\n", info.Provider)
			fmt.Printf("Host     : %s\n", info.Host)
			fmt.Printf("Version  : %s\n", info.Version)
			for k, v := range info.Extra {
				fmt.Printf("%-9s: %s\n", k, v)
			}
			return nil
		},
	}
	addProviderFlags(cmd)
	return cmd
}

func buildImportCmd(p providers.Provider) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import",
		Short: fmt.Sprintf("Import network topology from %s and generate a spec", p.Name()),
		RunE: func(_ *cobra.Command, _ []string) error {
			dur, _ := time.ParseDuration(timeout)
			if dur == 0 {
				dur = 60 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), dur)
			defer cancel()

			result, err := p.ImportSpec(ctx, providers.ImportOptions{
				Host:     providerHost,
				Username: providerUsername,
				Password: providerPassword,
				Site:     providerSite,
				Debug:    providerDebug,
			})
			if err != nil {
				return err
			}
			for _, w := range result.Warnings {
				fmt.Fprintf(os.Stderr, "Warning: %s\n", w)
			}
			fmt.Fprintf(os.Stderr, "Imported: %d networks, %d policies, %d clients\n",
				result.NetworkCount, result.PolicyCount, result.ClientCount)

			out, err := marshalSpecYAML(result, p.Name())
			if err != nil {
				return err
			}
			if providerOutFile != "" {
				if err := os.WriteFile(providerOutFile, out, 0600); err != nil {
					return fmt.Errorf("writing spec: %w", err)
				}
				fmt.Fprintf(os.Stderr, "Spec written to %s\n", providerOutFile)
				return nil
			}
			fmt.Print(string(out))
			return nil
		},
	}
	addProviderFlags(cmd)
	cmd.Flags().StringVar(&providerSite, "site", "", "Site name (defaults to first site)")
	cmd.Flags().StringVar(&providerOutFile, "out", "", "Write spec YAML to file (default: stdout)")
	cmd.Flags().BoolVar(&providerDebug, "debug", false, "Print raw API responses to stderr")
	return cmd
}

func buildCheckCmd(p providers.Provider) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check",
		Short: fmt.Sprintf("Import from %s and immediately run a live audit", p.Name()),
		RunE: func(_ *cobra.Command, _ []string) error {
			dur, _ := time.ParseDuration(timeout)
			if dur == 0 {
				dur = 300 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), dur)
			defer cancel()

			result, err := p.Check(ctx, providers.ImportOptions{
				Host:     providerHost,
				Username: providerUsername,
				Password: providerPassword,
				Site:     providerSite,
				Debug:    providerDebug,
			})
			if err != nil {
				return err
			}
			for _, w := range result.Warnings {
				fmt.Fprintf(os.Stderr, "Warning: %s\n", w)
			}

			w, err := getWriter()
			if err != nil {
				return err
			}
			if outputPath != "" {
				defer w.Close()
			}
			if jsonOutput {
				return report.RenderJSON(w, result.Report)
			}
			report.RenderHuman(w, result.Report)
			return nil
		},
	}
	addProviderFlags(cmd)
	cmd.Flags().StringVar(&providerSite, "site", "", "Site name")
	cmd.Flags().BoolVar(&providerDebug, "debug", false, "Print raw API responses to stderr")
	return cmd
}

func addProviderFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&providerHost, "host", "", "Controller IP or hostname")
	cmd.Flags().StringVar(&providerUsername, "username", "", "Admin username")
	cmd.Flags().StringVar(&providerPassword, "password", "", "Admin password")
}

func marshalSpecYAML(result *providers.ImportResult, providerName string) ([]byte, error) {
	specBytes, err := yaml.Marshal(result.Spec)
	if err != nil {
		return nil, fmt.Errorf("serializing spec: %w", err)
	}
	header := fmt.Sprintf("# Generated by nyx %s import\n# Host: %s  Version: %s\n\n",
		providerName, result.ProviderInfo.Host, result.ProviderInfo.Version)
	return append([]byte(header), specBytes...), nil
}

func init() {
	providerCmd.AddCommand(providerListCmd)
}
