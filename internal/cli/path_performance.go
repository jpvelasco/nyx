package cli

import (
	"context"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/spf13/cobra"
)

func newPerformanceCmd() *cobra.Command {
	var interval string
	cmd := topologyReadCommand(service.PerformanceCommand+" PATH-JSON", "Sample passive counters on selected path hops twice", cobra.ExactArgs(1), func(ctx context.Context, opts service.NetworkMapOptions, args []string) (any, error) {
		return service.SamplePerformance(ctx, opts, args[0], interval)
	})
	cmd.Flags().StringVar(&interval, "interval", "5s", "Time between samples (1s to 1m)")
	return cmd
}
