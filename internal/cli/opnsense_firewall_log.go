package cli

import (
	"context"

	"github.com/jpvelasco/nyx/internal/service"
	"github.com/spf13/cobra"
)

func buildOpnsenseFirewallLogCmd() *cobra.Command {
	var query service.OpnsenseFirewallLogQuery
	cmd := buildOpnsenseListCmd("firewall-log", "Read one page of logged OPNsense firewall packets", func(ctx context.Context, opts service.OpnsenseOptions) (any, error) {
		return service.NewOpnsenseService().FirewallLog(ctx, opts, query)
	})
	cmd.Args = cobra.NoArgs
	flags := cmd.Flags()
	flags.IntVar(&query.Limit, "limit", 1000, "Maximum controller records to examine (1–1000)")
	flags.StringVar(&query.Before, "before", "", "Previous page's next_before digest (within the newest 5000 records)")
	flags.StringVar(&query.Source, "src", "", "Source IP address or CIDR")
	flags.StringVar(&query.Destination, "dst", "", "Destination IP address or CIDR")
	flags.StringVar(&query.Action, "action", "", "Firewall action")
	flags.StringVar(&query.Direction, "dir", "", "Packet direction (in or out)")
	flags.StringVar(&query.Interface, "interface", "", "Firewall interface")
	flags.StringVar(&query.Since, "since", "", "Inclusive RFC3339 lower bound, with the firewall offset for local timestamps")
	return cmd
}

func buildOpnsenseFirewallLogStatsCmd() *cobra.Command {
	var limit int
	var groupBy string
	cmd := buildOpnsenseListCmd("firewall-log-stats", "Count recent OPNsense firewall log records by field", func(ctx context.Context, opts service.OpnsenseOptions) (any, error) {
		return service.NewOpnsenseService().FirewallLogStats(ctx, opts, limit, groupBy)
	})
	cmd.Args = cobra.NoArgs
	cmd.Flags().IntVar(&limit, "limit", 5000, "Maximum controller records to examine (1–5000)")
	cmd.Flags().StringVar(&groupBy, "group-by", "interface", "Firewall record field to group by")
	return cmd
}
