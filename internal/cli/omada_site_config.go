package cli

import (
	"context"
	"fmt"

	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/jpvelasco/nyx/internal/snapshot"
	"github.com/spf13/cobra"
)

func buildOmadaSiteConfigCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "site-config", Short: "Save and compare private site configuration baselines"}
	cmd.AddCommand(
		buildOmadaSiteConfigAction("snapshot", "Save the current site configuration as the baseline", func(cmd *cobra.Command, state omadabackend.SiteConfigState) error {
			if err := snapshot.SaveOmadaSiteConfig(state); err != nil {
				return err
			}
			if jsonOutput {
				return printJSON(map[string]bool{"saved": true})
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Site configuration baseline saved.")
			return nil
		}),
		buildOmadaSiteConfigAction("drift", "Compare the site configuration with the saved baseline", renderOmadaSiteConfigDrift),
	)
	return cmd
}

func buildOmadaSiteConfigAction(use, short string, action func(*cobra.Command, omadabackend.SiteConfigState) error) *cobra.Command {
	cmd := &cobra.Command{
		Use: use, Short: short, Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withProviderSession("omada", func(ctx context.Context, opts providers.ImportOptions) error {
				state, err := service.NewOmadaService().ReadSiteConfig(ctx, toOmadaOptions(opts))
				if err != nil {
					return err
				}
				return action(cmd, state)
			})
		},
	}
	addProviderFlags(cmd, "omada")
	return cmd
}

func renderOmadaSiteConfigDrift(cmd *cobra.Command, state omadabackend.SiteConfigState) error {
	changes, err := snapshot.CompareOmadaSiteConfig(state)
	if err != nil {
		return err
	}
	if jsonOutput {
		return printJSON(changes)
	}
	out := cmd.OutOrStdout()
	if len(changes) == 0 {
		fmt.Fprintln(out, "No site configuration changes since the baseline.")
	}
	for _, c := range changes {
		fmt.Fprintf(out, "%s %s %s\n", c.Status, c.Kind, c.Reference)
	}
	return nil
}
