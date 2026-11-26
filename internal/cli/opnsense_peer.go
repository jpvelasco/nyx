package cli

import (
	"context"

	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/spf13/cobra"
)

func opnsensePeerCommand(apply bool) *cobra.Command {
	req := service.WireGuardPeerRequest{}
	var enabled, dryRun bool
	name, short := "plan-wireguard-peer", "Preview one WireGuard peer configuration change"
	if apply {
		name, short = "revoke-wireguard-peer", "Disable or remove one selected WireGuard peer"
	}
	cmd := &cobra.Command{Use: name, Short: short, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		if cmd.Flags().Changed("enabled") {
			req.Enabled = &enabled
		}
		return withProviderSession("opnsense", func(ctx context.Context, opts providers.ImportOptions) error {
			result, err := service.NewOpnsenseService().RevokeWireGuardPeer(ctx, toOpnsenseOptions(opts), req, !apply || dryRun)
			if result != nil {
				if renderErr := printJSON(result); renderErr != nil {
					return renderErr
				}
			}
			return err
		})
	}}
	flags := cmd.Flags()
	flags.StringVar(&req.UUID, "uuid", "", "Select exactly one existing peer UUID")
	flags.StringVar(&req.Action, "action", "", "Peer action: create, update, toggle, or remove")
	flags.BoolVar(&enabled, "enabled", false, "Desired enabled state for toggle")
	if apply {
		flags.BoolVar(&dryRun, "dry-run", true, "Preview the revocation")
	} else {
		flags.StringVar(&req.Name, "name", "", "Peer name for a create preview")
		flags.StringSliceVar(&req.AllowedNetworks, "allowed-networks", nil, "Desired canonical IPv4 or IPv6 network prefixes")
	}
	addProviderFlags(cmd, "opnsense")
	return cmd
}
