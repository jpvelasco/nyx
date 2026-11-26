package cli

import (
	"context"

	"github.com/jpvelasco/nyx/internal/service"
	"github.com/spf13/cobra"
)

func newSwitchPortsCmd() *cobra.Command {
	return topologyReadCommand(service.SwitchPortsCommand+" CONNECTION SWITCH-MAC POLICY-JSON", "Preview access-port and AP uplink VLAN intents for one managed switch", cobra.ExactArgs(3), func(ctx context.Context, opts service.NetworkMapOptions, args []string) (any, error) {
		policy, err := service.DecodeSwitchPortPolicy(args[2])
		if err != nil {
			return nil, err
		}
		return service.NewTopologyService().PlanSwitchPorts(ctx, opts, args[0], args[1], policy)
	})
}
