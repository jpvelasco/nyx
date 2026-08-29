package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jpvelasco/nyx/internal/credentials"
	providers "github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/report"
	"github.com/jpvelasco/nyx/internal/storepath"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	providerHost         string
	providerClientID     string
	providerClientSecret string
	providerSite         string
	providerDebug        bool
	providerOutFile      string
	providerSkipTLS      bool
	providerCACertPath   string
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
		if caps["inventory"] {
			vendorCmd.AddCommand(buildInventoryCmd(p))
		}

		root.AddCommand(vendorCmd)
	}
}

func buildInfoCmd(p providers.Provider) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "info",
		Short: fmt.Sprintf("Show %s controller version and connection info", p.Name()),
		RunE: func(_ *cobra.Command, _ []string) error {
			opts := providerImportOptions(p.Name())
			if err := requireProviderHost(opts, p.Name()); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			info, err := p.Info(ctx, opts)
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
			dur, err := parseTimeoutFlag(timeout)
			if err != nil {
				return err
			}
			if dur == 0 {
				dur = 60 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), dur)
			defer cancel()

			opts := providerImportOptions(p.Name())
			opts.Debug = providerDebug
			if err := requireProviderHost(opts, p.Name()); err != nil {
				return err
			}
			result, err := p.ImportSpec(ctx, opts)
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
				//nolint:gosec
				if err := os.WriteFile(providerOutFile, out, 0600); err != nil { // nosemgrep
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
			dur, err := parseTimeoutFlag(timeout)
			if err != nil {
				return err
			}
			if dur == 0 {
				dur = 300 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), dur)
			defer cancel()

			opts := providerImportOptions(p.Name())
			opts.Debug = providerDebug
			if err := requireProviderHost(opts, p.Name()); err != nil {
				return err
			}
			result, err := p.Check(ctx, opts)
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
				return renderAuditReport(w, result.Report)
			}
			report.RenderHuman(w, result.Report)
			return statusExitError(result.Report.Status)
		},
	}
	addProviderFlags(cmd)
	cmd.Flags().StringVar(&providerSite, "site", "", "Site name")
	cmd.Flags().BoolVar(&providerDebug, "debug", false, "Print raw API responses to stderr")
	return cmd
}

func buildInventoryCmd(p providers.Provider) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inventory",
		Short: fmt.Sprintf("Show the current %s site inventory (devices, networks, ACL scopes, clients)", p.Name()),
		RunE: func(_ *cobra.Command, _ []string) error {
			inv, ok := p.(providers.InventoryProvider)
			if !ok {
				return fmt.Errorf("provider %q does not support inventory", p.Name())
			}
			dur, err := parseTimeoutFlag(timeout)
			if err != nil {
				return err
			}
			if dur == 0 {
				dur = 60 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), dur)
			defer cancel()

			opts := providerImportOptions(p.Name())
			if err := requireProviderHost(opts, p.Name()); err != nil {
				return err
			}
			res, err := inv.Inventory(ctx, opts)
			if err != nil {
				return err
			}
			for _, w := range res.Warnings {
				fmt.Fprintf(os.Stderr, "Warning: %s\n", w)
			}
			if jsonOutput {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(res)
			}
			fmt.Print(res.Human)
			return nil
		},
	}
	addProviderFlags(cmd)
	cmd.Flags().StringVar(&providerSite, "site", "", "Site name (defaults to first site)")
	return cmd
}

// providerEnvNames lists the per-provider env var names for the credential
// fields. The opnsense provider carries the API pair under OPNSENSE_API_KEY /
// OPNSENSE_API_SECRET (matching `nyx topology`) and has no site.
//
// #nosec G101 — env var names, not credential values
const (
	omadaHostEnv = "OMADA_HOST"
	// #nosec G101
	omadaCredEnv = "OMADA_CLIENT_ID / OMADA_CLIENT_SECRET"
)

var providerEnvNames = map[string][4]string{
	// host, credential 1, credential 2, site
	"omada":    {"OMADA_HOST", "OMADA_CLIENT_ID", "OMADA_CLIENT_SECRET", "OMADA_SITE"},
	"opnsense": {"OPNSENSE_HOST", "OPNSENSE_API_KEY", "OPNSENSE_API_SECRET", ""},
}

// providerImportOptions builds ImportOptions from flags, then per-provider
// env vars, then the encrypted credential store. Flags win over env; env
// wins over the store. Missing host after all three is left empty so the
// provider surfaces its own connection error.
func providerImportOptions(providerName string) providers.ImportOptions {
	names, ok := providerEnvNames[providerName]
	// Unknown providers keep the historical omada env names.
	if !ok {
		names = providerEnvNames["omada"]
	}
	opts := providers.ImportOptions{
		Host:          storepath.FirstNonEmpty(providerHost, os.Getenv(names[0])),
		ClientID:      storepath.FirstNonEmpty(providerClientID, os.Getenv(names[1])),
		ClientSecret:  storepath.FirstNonEmpty(providerClientSecret, os.Getenv(names[2])),
		Site:          storepath.FirstNonEmpty(providerSite, os.Getenv(names[3])),
		SkipTLSVerify: providerSkipTLS,
		CACertPath:    providerCACertPath,
		Logger:        log,
	}
	// Overlay is fill-only: a partial store entry must never clear values
	// already resolved from flags or env vars.
	if opts.Host == "" || opts.ClientID == "" || opts.ClientSecret == "" {
		fields := credentials.Fields{
			Host:         opts.Host,
			ClientID:     opts.ClientID,
			ClientSecret: opts.ClientSecret,
			Site:         opts.Site,
			APIKey:       opts.ClientID,
			APISecret:    opts.ClientSecret,
		}
		credentials.Overlay(storepath.StoreFile(), providerName, "default", &fields)
		opts.Host = fields.Host
		opts.Site = fields.Site
		if providerName == "opnsense" {
			opts.ClientID = fields.APIKey
			opts.ClientSecret = fields.APISecret
		} else {
			if fields.ClientID != "" {
				opts.ClientID = fields.ClientID
			}
			if fields.ClientSecret != "" {
				opts.ClientSecret = fields.ClientSecret
			}
		}
	}
	return opts
}

// requireProviderHost errors when no host was resolved from flags, env, or
// the store, naming the provider's env vars in the hint.
func requireProviderHost(opts providers.ImportOptions, providerName string) error {
	if opts.Host != "" {
		return nil
	}
	hostEnv, credEnv := omadaHostEnv, omadaCredEnv
	providerName = strings.ToLower(providerName)
	if names, ok := providerEnvNames[providerName]; ok && names[0] != "" {
		hostEnv = names[0]
		credEnv = names[1] + " / " + names[2]
	}
	return fmt.Errorf("controller host is required: pass --host, set %s, or run `nyx credentials set %s --set host=...` (credentials: %s)",
		hostEnv, providerName, credEnv)
}

func addProviderFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&providerHost, "host", "", "Controller IP or hostname")
	cmd.Flags().StringVar(&providerClientID, "client-id", "", "Omada Open API client ID")
	cmd.Flags().StringVar(&providerClientSecret, "client-secret", "", "Omada Open API client secret")
	cmd.Flags().BoolVar(&providerSkipTLS, "skip-tls-verify", false, "Skip TLS certificate verification (like curl -k)")
	cmd.Flags().StringVar(&providerCACertPath, "ca-cert", "", "Path to custom CA certificate PEM file")
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
