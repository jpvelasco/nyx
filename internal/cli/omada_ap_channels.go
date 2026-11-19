package cli

import (
	"context"
	"fmt"
	"maps"
	"slices"

	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/spf13/cobra"
)

func buildOmadaAPChannelsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ap-channel-info",
		Short: "List current and available channels for site access points",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return withProviderSession("omada", func(ctx context.Context, opts providers.ImportOptions) error {
				rows, err := service.NewOmadaService().ListAPChannels(ctx, toOmadaOptions(opts))
				if err != nil {
					return err
				}
				if jsonOutput {
					return printJSON(rows)
				}
				out := cmd.OutOrStdout()
				if len(rows) == 0 {
					fmt.Fprintln(out, "No managed access points found.")
				}
				for _, row := range rows {
					fmt.Fprintf(out, "%s (%s)\n", row.Name, shortMAC(row.MAC))
					for _, band := range slices.Sorted(maps.Keys(row.CurrentChannels)) {
						fmt.Fprintf(out, "  %s: %s\n", band, row.CurrentChannels[band])
					}
					fmt.Fprintf(out, "  Available channels: %s\n", row.AvailableChannels)
				}
				return nil
			})
		},
	}
	addProviderFlags(cmd, "omada")
	return cmd
}
