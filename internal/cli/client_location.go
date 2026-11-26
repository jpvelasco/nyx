package cli

import (
	"context"

	"github.com/jpvelasco/nyx/internal/service"
	"github.com/spf13/cobra"
)

func newClientLocationCmd() *cobra.Command {
	return topologyReadCommand(service.ClientLocationCommand+" MAC", "Locate a client's last observable managed attachment", cobra.ExactArgs(1), func(ctx context.Context, opts service.NetworkMapOptions, args []string) (any, error) {
		return service.NewTopologyService().LocateClient(ctx, opts, args[0])
	})
}
