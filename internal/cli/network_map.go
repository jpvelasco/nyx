package cli

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/jpvelasco/nyx/internal/service"
	"github.com/spf13/cobra"
)

func newNetworkMapCmd() *cobra.Command {
	return topologyReadCommand(service.NetworkMapCommand, "Map devices, ports, VLANs, SSIDs and serving gateways from configured controller inventories", cobra.NoArgs, func(ctx context.Context, opts service.NetworkMapOptions, _ []string) (any, error) {
		return service.NewTopologyService().Map(ctx, opts)
	})
}

func topologyReadCommand(use, short string, args cobra.PositionalArgs, read func(context.Context, service.NetworkMapOptions, []string) (any, error)) *cobra.Command {
	var opts service.NetworkMapOptions
	cmd := &cobra.Command{
		Use: use, Short: short, Args: args,
		RunE: func(cmd *cobra.Command, args []string) error {
			dur, err := extraTimeout()
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), dur)
			defer cancel()
			opts.Logger = slog.Default()
			result, err := read(ctx, opts, args)
			if err != nil {
				return err
			}
			w, err := getWriter()
			if err != nil {
				return err
			}
			if outputPath != "" {
				defer w.Close()
			}
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			return enc.Encode(result)
		},
	}
	cmd.Flags().StringArrayVar(&opts.Connections, "connection", nil, "Provider or provider/profile to observe (repeatable; defaults to configured connections)")
	cmd.Flags().BoolVar(&opts.Detail, "detail", false, "Include private source names, controller resource IDs and addressing")
	cmd.Flags().BoolVar(&opts.SkipTLSVerify, "skip-tls-verify", false, "Skip controller TLS certificate verification")
	cmd.Flags().StringVar(&opts.CACertPath, "ca-cert", "", "Path to a custom controller CA certificate")
	return cmd
}
