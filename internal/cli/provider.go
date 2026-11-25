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
	"github.com/jpvelasco/nyx/internal/intent"
	providers "github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/report"
	"github.com/jpvelasco/nyx/internal/storepath"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	providerProfile      string
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

		// Extra (non-capability) surface: observation + plan/apply
		// mutations. They are not advertised via Capabilities() —
		// adding them there would trip the capability parity gate.
		switch p.Name() {
		case "omada":
			for _, extra := range buildOmadaExtraCommands() {
				vendorCmd.AddCommand(extra)
			}
		case "opnsense":
			for _, extra := range buildOpnsenseExtraCommands() {
				vendorCmd.AddCommand(extra)
			}
		}

		root.AddCommand(vendorCmd)
	}
}

func buildInfoCmd(p providers.Provider) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "info",
		Short: fmt.Sprintf("Show %s controller version and connection info", p.Name()),
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts := providerCommandOptions(cmd, p.Name())
			if err := validateProviderOptions(opts, p.Name(), p.Name() != "omada"); err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			info, err := p.Info(ctx, opts)
			if err != nil {
				return opts.Connection.RedactError(err, opts.Credentials)
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
	addProviderFlags(cmd, p.Name())
	return cmd
}

func buildImportCmd(p providers.Provider) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import",
		Short: fmt.Sprintf("Import network topology from %s and generate a spec", p.Name()),
		RunE: func(cmd *cobra.Command, _ []string) error {
			dur, err := parseTimeoutFlag(timeout)
			if err != nil {
				return err
			}
			if dur == 0 {
				dur = 60 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), dur)
			defer cancel()

			opts := providerCommandOptions(cmd, p.Name())
			opts.Debug = providerDebug
			if err := requireProviderConnection(opts, p.Name()); err != nil {
				return err
			}
			result, err := p.ImportSpec(ctx, opts)
			if err != nil {
				return opts.Connection.RedactError(err, opts.Credentials)
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
	addProviderFlags(cmd, p.Name())
	cmd.Flags().StringVar(&providerSite, "site", "", "Site name (defaults to first site)")
	cmd.Flags().StringVar(&providerOutFile, "out", "", "Write spec YAML to file (default: stdout)")
	cmd.Flags().BoolVar(&providerDebug, "debug", false, "Print raw API responses to stderr")
	return cmd
}

func buildCheckCmd(p providers.Provider) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check",
		Short: fmt.Sprintf("Import from %s and immediately run a live audit", p.Name()),
		RunE: func(cmd *cobra.Command, _ []string) error {
			dur, err := parseTimeoutFlag(timeout)
			if err != nil {
				return err
			}
			if dur == 0 {
				dur = 300 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), dur)
			defer cancel()

			opts := providerCommandOptions(cmd, p.Name())
			opts.Debug = providerDebug
			if err := requireProviderConnection(opts, p.Name()); err != nil {
				return err
			}
			result, err := p.Check(ctx, opts)
			if err != nil {
				return opts.Connection.RedactError(err, opts.Credentials)
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
			includeACLNames, _ := cmd.Flags().GetBool("include-acl-names")
			if !includeACLNames {
				result.Report = report.OmitControllerACLNames(result.Report)
			}
			if jsonOutput {
				return renderAuditReport(w, result.Report)
			}
			report.RenderHuman(w, result.Report)
			return statusExitError(result.Report.Status)
		},
	}
	addProviderFlags(cmd, p.Name())
	cmd.Flags().Bool("include-acl-names", false, "Include private controller ACL labels in the audit report")
	cmd.Flags().StringVar(&providerSite, "site", "", "Site name")
	cmd.Flags().BoolVar(&providerDebug, "debug", false, "Print raw API responses to stderr")
	return cmd
}

func buildInventoryCmd(p providers.Provider) *cobra.Command {
	var includeFirewallDetails bool
	var inventorySpec string
	cmd := &cobra.Command{
		Use:   "inventory",
		Short: fmt.Sprintf("Show the current %s site inventory (devices, networks, ACL scopes, clients)", p.Name()),
		RunE: func(cmd *cobra.Command, _ []string) error {
			var segmentEdges []intent.SegmentEdge
			if inventorySpec != "" {
				spec, err := intent.LoadSpec(inventorySpec)
				if err != nil {
					return err
				}
				segmentEdges = spec.SegmentEdges()
			}
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

			opts := providerCommandOptions(cmd, p.Name())
			opts.Debug = providerDebug
			opts.IncludeFirewallDetails = includeFirewallDetails
			if err := requireProviderConnection(opts, p.Name()); err != nil {
				return err
			}
			res, err := inv.Inventory(ctx, opts)
			if err != nil {
				return opts.Connection.RedactError(err, opts.Credentials)
			}
			for _, w := range res.Warnings {
				fmt.Fprintf(os.Stderr, "Warning: %s\n", w)
			}
			if jsonOutput {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				if len(segmentEdges) > 0 {
					return enc.Encode(struct {
						*providers.ProviderInventory
						SegmentEdges []intent.SegmentEdge `json:"segment_edges"`
					}{res, segmentEdges})
				}
				return enc.Encode(res)
			}
			fmt.Print(res.Human)
			for _, segment := range segmentEdges {
				fmt.Printf("  %s: edge=%s", segment.Network, segment.Edge)
				if segment.Observer != "" {
					fmt.Printf(" observer=%s", segment.Observer)
				}
				fmt.Println()
			}
			return nil
		},
	}
	addProviderFlags(cmd, p.Name())
	cmd.Flags().StringVar(&providerSite, "site", "", "Site name (defaults to first site)")
	cmd.Flags().BoolVar(&providerDebug, "debug", false, "Print raw API responses to stderr")
	if p.Name() == "opnsense" {
		cmd.Flags().BoolVar(&includeFirewallDetails, "include-firewall-details", false, "Include private rule endpoints and configured alias members")
	}
	cmd.Flags().StringVar(&inventorySpec, "spec", "", "Include declared segment edge and observer relationships")
	return cmd
}

// The built-in option fields retain the existing flags. New adapters read their
// own declared fields from the command that was invoked.
func providerCommandOptions(cmd *cobra.Command, name string) providers.ImportOptions {
	values := credentials.Entry{"host": providerHost, "site": providerSite}
	switch name {
	case "omada":
		values["client_id"], values["client_secret"] = providerClientID, providerClientSecret
	case "opnsense":
		values["api_key"], values["api_secret"] = providerClientID, providerClientSecret
	default:
		if cmd != nil {
			for _, field := range credentials.FieldsFor(name) {
				if field.Name != "host" && field.Name != "site" {
					values[field.Name], _ = cmd.Flags().GetString(strings.ReplaceAll(field.Name, "_", "-"))
				}
			}
		}
	}
	c := credentials.Connection{Provider: name, Profile: providerProfile}
	authenticated := cmd == nil || cmd.Name() != "info" || name != "omada"
	// CLI info accepts a host from the default store.
	if !authenticated {
		c.Profile = c.ProfileName()
	}
	opts := providers.ConnectionOptions(c, credentials.Resolve(c, values, os.Getenv, storepath.StoreFile(), authenticated))
	opts.SkipTLSVerify, opts.CACertPath, opts.Logger = providerSkipTLS, providerCACertPath, slogLog
	return opts
}

func providerImportOptions(name string) providers.ImportOptions {
	return providerCommandOptions(nil, name)
}

func requireProviderConnection(opts providers.ImportOptions, name string) error {
	return validateProviderOptions(opts, name, true)
}

func validateProviderOptions(opts providers.ImportOptions, name string, authenticated bool) error {
	if authenticated && (opts.Connection.ProfileName() != "default" || (name != "omada" && name != "opnsense")) {
		if err := opts.Connection.Require(opts.Credentials); err != nil {
			return err
		}
	}
	return requireProviderHost(opts, name)
}

func requireProviderHost(opts providers.ImportOptions, providerName string) error {
	if opts.Host != "" {
		return nil
	}
	var envs []string
	for _, f := range credentials.FieldsFor(providerName) {
		if f.Required && f.Env != "" {
			envs = append(envs, f.Env)
		}
	}
	hint := ""
	if len(envs) > 0 && opts.Connection.ProfileName() == "default" {
		hint = "set " + strings.Join(envs, " / ") + ", "
	}
	return fmt.Errorf("controller host is required: pass --host, %sor run `nyx credentials set %s %s --set host=...`", hint, providerName, opts.Connection.ProfileName())
}

func addProviderFlags(cmd *cobra.Command, providerName string) {
	flags := cmd.Flags()
	flags.StringVar(&providerHost, "host", "", "Controller IP or hostname")
	flags.StringVar(&providerProfile, "profile", "", "Named credential profile (defaults to default)")
	for _, f := range credentials.FieldsFor(providerName) {
		var dest *string
		switch {
		case f.Name == "host" || f.Name == "site":
			continue
		case providerName == "omada" && f.Name == "client_id", providerName == "opnsense" && f.Name == "api_key":
			dest = &providerClientID
		case providerName == "omada" && f.Name == "client_secret", providerName == "opnsense" && f.Name == "api_secret":
			dest = &providerClientSecret
		default:
			dest = new(string)
		}
		flags.StringVar(dest, strings.ReplaceAll(f.Name, "_", "-"), "", f.Description)
	}
	flags.BoolVar(&providerSkipTLS, "skip-tls-verify", false, "Skip TLS certificate verification (like curl -k)")
	flags.StringVar(&providerCACertPath, "ca-cert", "", "Path to custom CA certificate PEM file")
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
