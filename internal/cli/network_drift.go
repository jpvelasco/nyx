package cli

import (
	"context"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/spf13/cobra"
)

func newMapCaptureCmd() *cobra.Command {
	var audit string
	var replace bool
	cmd := topologyReadCommand(service.MapCaptureCommand+" NAME", "Save a private network map in the local snapshot store", cobra.ExactArgs(1), func(ctx context.Context, opts service.NetworkMapOptions, args []string) (any, error) {
		return service.NewTopologyService().CaptureMap(ctx, opts, args[0], audit, replace)
	})
	cmd.Flags().StringVar(&audit, "audit-snapshot", "", "Named Nyx audit snapshot containing service-policy evidence")
	cmd.Flags().BoolVar(&replace, "replace", false, "Replace this named map snapshot")
	return cmd
}
func newMapDriftCmd() *cobra.Command {
	var audit, maxAge string
	cmd := topologyReadCommand(service.MapDriftCommand+" BEFORE [AFTER]", "Compare a saved map with another capture or with current inventory", cobra.RangeArgs(1, 2), func(ctx context.Context, opts service.NetworkMapOptions, args []string) (any, error) {
		var after string
		if len(args) > 1 {
			after = args[1]
		}
		return service.NewTopologyService().MapDrift(ctx, opts, args[0], after, audit, maxAge)
	})
	cmd.Flags().StringVar(&audit, "audit-snapshot", "", "Named audit snapshot for the current read")
	cmd.Flags().StringVar(&maxAge, "max-age", "24h", "Maximum observation age at the time each map was captured")
	return cmd
}
