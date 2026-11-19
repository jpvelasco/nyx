package cli

import (
	"context"
	"fmt"

	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
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
	cmd.AddCommand(buildOmadaLogsExportCmd())
	addProviderFlags(cmd, "omada")
	return cmd
}

func buildOmadaLogsExportCmd() *cobra.Command {
	var (
		format string
		out    string
	)
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export the site log archive (zip) from the controller",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			var code int
			switch format {
			case "csv":
				code = omadabackend.LogExportCSV
			case "xlsx":
				code = omadabackend.LogExportXLSX
			default:
				return fmt.Errorf("--format must be csv or xlsx")
			}
			return withProviderSession("omada", func(ctx context.Context, opts providers.ImportOptions) error {
				res, err := service.NewOmadaService().ExportLogs(ctx, toOmadaOptions(opts), code, out)
				if err != nil {
					return err
				}
				return printJSON(res)
			})
		},
	}
	cmd.Flags().StringVar(&format, "format", "csv", "Export format (csv or xlsx)")
	cmd.Flags().StringVar(&out, "out", "", "Path to save the archive (defaults to the controller-supplied filename)")
	addProviderFlags(cmd, "omada")
	return cmd
}
