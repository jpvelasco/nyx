package cli

import (
	"context"

	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/spf13/cobra"
)

func buildOmadaLogsCmd() *cobra.Command {
	var query service.OmadaEventLogQuery
	cmd := &cobra.Command{
		Use: "logs", Short: "Read a page of site event logs as JSON", Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return withProviderSession("omada", func(ctx context.Context, opts providers.ImportOptions) error {
				page, err := service.NewOmadaService().ListEventLogs(ctx, toOmadaOptions(opts), query)
				if err != nil {
					return err
				}
				return printJSON(page)
			})
		},
	}
	cmd.Flags().StringVar(&query.Module, "module", "", "Event module (System, Device, or Client)")
	cmd.Flags().StringVar(&query.Since, "since", "", "Lookback duration (for example 30d, default 24h)")
	cmd.Flags().StringVar(&query.TimeStart, "time-start", "", "Start of the range (RFC3339, instead of --since)")
	cmd.Flags().StringVar(&query.TimeEnd, "time-end", "", "End of the range (RFC3339, defaults to now)")
	cmd.Flags().IntVar(&query.Page, "page", 1, "Page number")
	cmd.Flags().IntVar(&query.PageSize, "page-size", 50, "Events per page (1–1000)")
	addProviderFlags(cmd, "omada")
	return cmd
}
