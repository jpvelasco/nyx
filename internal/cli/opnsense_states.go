package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/providers/opnsense"
	"github.com/spf13/cobra"
)

func buildOpnsenseStatesCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "states", Short: "Inspect or manage the pf state table"}
	cmd.AddCommand(buildOpnsenseStateList(), buildOpnsenseStateKill(),
		buildOpnsenseStateOperation("flush-states", "Clear all firewall states", (*opnsense.Client).FlushStates),
		buildOpnsenseStateOperation("flush-sources", "Clear pf source tracking", (*opnsense.Client).FlushSources),
		buildOpnsenseStateRead("rule-ids", "List pf rule IDs and descriptions", func(ctx context.Context, c *opnsense.Client) (any, error) { return c.StateRuleIDs(ctx) }),
		buildOpnsenseStateRead("capacity", "Show pf state usage and limit", func(ctx context.Context, c *opnsense.Client) (any, error) { return c.StateCapacity(ctx) }),
	)
	return cmd
}

func buildOpnsenseStateList() *cobra.Command {
	var q opnsense.StateQuery
	var sort string
	cmd := &cobra.Command{Use: "list", Short: "Query a page of firewall states", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
		q.Sort = nil
		if sort != "" {
			field, order, ok := strings.Cut(sort, ":")
			if !ok {
				return fmt.Errorf("--sort requires field:asc or field:desc")
			}
			q.Sort = map[string]string{field: order}
		}
		return withOpnsenseStateClient(func(ctx context.Context, c *opnsense.Client) (any, error) { return c.QueryStates(ctx, q) })
	}}
	cmd.Flags().StringVar(&q.Search, "search", "", "Search tokens, matched together")
	cmd.Flags().StringVar(&q.RuleID, "rule-id", "", "Filter by pf rule ID")
	cmd.Flags().StringVar(&sort, "sort", "", "Sort one field using field:asc or field:desc")
	cmd.Flags().IntVar(&q.Page, "page", 1, "Page number")
	cmd.Flags().IntVar(&q.PageSize, "page-size", 9999, "Maximum rows per page (1–9999)")
	addProviderFlags(cmd, "opnsense")
	return cmd
}

func buildOpnsenseStateKill() *cobra.Command {
	var state, filter, ruleID string
	cmd := buildOpnsenseStateOperation("kill", "Delete a specific state or kill matching states", func(c *opnsense.Client, ctx context.Context) (opnsense.StateOperationResult, error) {
		if state != "" {
			return c.DeleteState(ctx, state)
		}
		return c.KillStates(ctx, filter, ruleID)
	})
	cmd.PreRunE = func(cmd *cobra.Command, _ []string) error {
		single := cmd.Flags().Changed("state")
		scoped := cmd.Flags().Changed("filter") || cmd.Flags().Changed("rule-id")
		if single == scoped || (single && state == "") || (scoped && strings.TrimSpace(filter) == "" && ruleID == "") {
			return fmt.Errorf("supply --state or a nonempty --filter and/or --rule-id")
		}
		return nil
	}
	cmd.Flags().StringVar(&state, "state", "", "Exact creator/state hexadecimal ID from list output")
	cmd.Flags().StringVar(&filter, "filter", "", "Kill matching states using search tokens")
	cmd.Flags().StringVar(&ruleID, "rule-id", "", "Kill states for this pf rule ID")
	return cmd
}

func buildOpnsenseStateOperation(use, short string, op func(*opnsense.Client, context.Context) (opnsense.StateOperationResult, error)) *cobra.Command {
	var confirm bool
	cmd := &cobra.Command{Use: use, Short: short, Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
		if !confirm {
			return fmt.Errorf("%s requires --confirm because it can interrupt active connections", use)
		}
		return withOpnsenseStateClient(func(ctx context.Context, c *opnsense.Client) (any, error) { return op(c, ctx) })
	}}
	cmd.Flags().BoolVar(&confirm, "confirm", false, "Execute this operation on the state table")
	addProviderFlags(cmd, "opnsense")
	return cmd
}

func withOpnsenseStateClient(fn func(context.Context, *opnsense.Client) (any, error)) error {
	return withProviderSession("opnsense", func(ctx context.Context, opts providers.ImportOptions) error {
		result, err := fn(ctx, opnsense.NewClient(opts.Host, opts.ClientID, opts.ClientSecret, opts.SkipTLSVerify, opts.CACertPath))
		if err != nil {
			return err
		}
		return printJSON(result)
	})
}

func buildOpnsenseStateRead(use, short string, fn func(context.Context, *opnsense.Client) (any, error)) *cobra.Command {
	cmd := &cobra.Command{Use: use, Short: short, Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error { return withOpnsenseStateClient(fn) }}
	addProviderFlags(cmd, "opnsense")
	return cmd
}
