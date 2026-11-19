package cli

import (
	"context"

	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/spf13/cobra"
)

func buildOpnsenseBlocklistCmd() *cobra.Command {
	group := &cobra.Command{Use: "blocklist", Short: "Inspect and administer OPNsense runtime pf tables"}
	svc := service.NewOpnsenseService()
	add := func(use, short string, count int, fetch func(context.Context, service.OpnsenseOptions, []string) (any, error)) *cobra.Command {
		cmd := &cobra.Command{Use: use, Short: short, Args: cobra.ExactArgs(count), RunE: func(_ *cobra.Command, args []string) error {
			return withProviderSession("opnsense", func(ctx context.Context, opts providers.ImportOptions) error {
				result, err := fetch(ctx, toOpnsenseOptions(opts), args)
				if err != nil {
					return err
				}
				return printJSON(result)
			})
		}}
		addProviderFlags(cmd, "opnsense")
		group.AddCommand(cmd)
		return cmd
	}
	add("list-tables", "List runtime pf table names", 0, func(ctx context.Context, opts service.OpnsenseOptions, _ []string) (any, error) {
		return svc.ListBlocklistTables(ctx, opts)
	})
	var search string
	list := add("list <table>", "List entries in a runtime table", 1, func(ctx context.Context, opts service.OpnsenseOptions, args []string) (any, error) {
		return svc.ListBlocklist(ctx, opts, args[0], search)
	})
	list.Flags().StringVar(&search, "search", "", "Filter table entries")
	add("references <ip>", "Find firewall references to an IP address", 1, func(ctx context.Context, opts service.OpnsenseOptions, args []string) (any, error) {
		return svc.BlocklistReferences(ctx, opts, args[0])
	})
	var unblockConfirm, flushConfirm bool
	unblock := add("unblock <table> <ip-or-cidr>", "Preview or remove one table entry", 2, func(ctx context.Context, opts service.OpnsenseOptions, args []string) (any, error) {
		return svc.UpdateBlocklist(ctx, opts, "unblock", args[0], args[1], unblockConfirm)
	})
	unblock.Flags().BoolVar(&unblockConfirm, "confirm", false, "Remove the specified entry")
	flush := add("flush <table>", "Preview or clear all entries in one table", 1, func(ctx context.Context, opts service.OpnsenseOptions, args []string) (any, error) {
		return svc.UpdateBlocklist(ctx, opts, "flush", args[0], "", flushConfirm)
	})
	flush.Flags().BoolVar(&flushConfirm, "confirm", false, "Clear every entry in the named table")
	return group
}
