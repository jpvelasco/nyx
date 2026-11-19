package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/spf13/cobra"
)

func buildOmadaAttackDefenseCmd() *cobra.Command {
	var mac string
	cmd := &cobra.Command{Use: "attack-defense", Short: "Read site attack-defense settings and report the gateway runtime boundary", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
		return withProviderSession("omada", func(ctx context.Context, opts providers.ImportOptions) error {
			report, err := service.NewOmadaService().AttackDefense(ctx, toOmadaOptions(opts), mac)
			if err != nil {
				return err
			}
			return printJSON(report)
		})
	}}
	cmd.Flags().StringVar(&mac, "mac", "", "Also read the administrative block flag for this client MAC")
	addProviderFlags(cmd, "omada")
	return cmd
}

func buildOmadaUnblockClientCmd() *cobra.Command {
	var mac string
	var confirm bool
	cmd := &cobra.Command{Use: "unblock-client", Short: "Remove a single controller-managed client block", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
		if !confirm {
			return errors.New("unblock-client requires --confirm")
		}
		if mac == "" {
			return errors.New("unblock-client requires --mac")
		}
		return withProviderSession("omada", func(ctx context.Context, opts providers.ImportOptions) error {
			if err := service.NewOmadaService().UnblockClient(ctx, toOmadaOptions(opts), mac); err != nil {
				return err
			}
			const message = "Controller client unblock accepted. Inspect the gateway separately for runtime attack-defense blocks."
			if jsonOutput {
				return printJSON(map[string]string{"status": "accepted", "guidance": message})
			}
			fmt.Println(message)
			return nil
		})
	}}
	cmd.Flags().StringVar(&mac, "mac", "", "Client MAC to unblock")
	cmd.Flags().BoolVar(&confirm, "confirm", false, "Apply the controller client unblock")
	addProviderFlags(cmd, "omada")
	return cmd
}
