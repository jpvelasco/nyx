package cli

import (
	"context"
	"time"

	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/spf13/cobra"
)

func buildOmadaPendingDevicesCmd() *cobra.Command {
	var page, size int
	var private bool
	cmd := &cobra.Command{Use: "pending-devices", Short: "List pending devices in one page of the selected site", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
		return withProviderSession("omada", func(ctx context.Context, opts providers.ImportOptions) error {
			r, err := service.NewOmadaService().PendingDevices(ctx, toOmadaOptions(opts), page, size, private)
			if err != nil {
				return err
			}
			return printJSON(r)
		})
	}}
	cmd.Flags().IntVar(&page, "page", 1, "Page number")
	cmd.Flags().IntVar(&size, "page-size", 25, "Rows per page (1 to 100)")
	cmd.Flags().BoolVar(&private, "include-private-details", false, "Include device MAC for selection")
	cmd.Flags().StringVar(&providerSite, "site", "", "Explicit Omada site")
	addProviderFlags(cmd, "omada")
	return cmd
}
func buildOmadaAdoptionStatusCmd() *cobra.Command {
	var mac string
	var wait time.Duration
	cmd := &cobra.Command{Use: "adoption-status", Short: "Observe adoption of an exact device at the selected site", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
		return withProviderSession("omada", func(ctx context.Context, opts providers.ImportOptions) error {
			r, err := service.NewOmadaService().ObserveAdoption(ctx, toOmadaOptions(opts), mac, wait)
			if err != nil {
				return err
			}
			return printJSON(r)
		})
	}}
	cmd.Flags().StringVar(&mac, "mac", "", "Exact device MAC")
	cmd.Flags().DurationVar(&wait, "wait", 0, "Maximum observation time (up to two minutes)")
	cmd.Flags().StringVar(&providerSite, "site", "", "Explicit Omada site")
	addProviderFlags(cmd, "omada")
	return cmd
}
