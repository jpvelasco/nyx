package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/jpvelasco/nyx/internal/service"
	"github.com/jpvelasco/nyx/internal/storepath"
	"github.com/spf13/cobra"
)

func providerCapabilitiesCmd() *cobra.Command {
	var opts service.CapabilityOptions
	cmd := &cobra.Command{Use: service.CapabilitiesCommand, Short: "List provider operations and configured connections", RunE: func(cmd *cobra.Command, _ []string) error {
		duration, err := extraTimeout()
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), duration)
		defer cancel()
		result, err := service.ProviderCapabilityReport(ctx, opts, storepath.StoreFile(), os.Getenv)
		if err != nil {
			return err
		}
		out := cmd.OutOrStdout()
		if jsonOutput {
			return json.NewEncoder(out).Encode(result)
		}
		for _, p := range result {
			fmt.Fprintf(out, "%s  %s\n", p.Provider, strings.Join(p.Operations, ", "))
			for _, c := range p.Connections {
				fmt.Fprintf(out, "  %s  site=%s  info=%s\n", c.Profile, c.LogicalSite, c.InfoAccess)
			}
		}
		return nil
	}}
	cmd.Flags().StringVar(&opts.Provider, "provider", "", "Restrict discovery to this provider")
	cmd.Flags().StringVar(&opts.Profile, "profile", "", "Restrict discovery to this connection profile")
	cmd.Flags().BoolVar(&opts.Observe, "observe", false, "Verify controller information read access")
	cmd.Flags().BoolVar(&opts.SkipTLSVerify, "skip-tls-verify", false, "Skip TLS certificate verification")
	cmd.Flags().StringVar(&opts.CACertPath, "ca-cert", "", "Path to the controller CA certificate")
	return cmd
}
