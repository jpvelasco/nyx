package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	providers "github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/spf13/cobra"
)

// extraTimeout parses the global --timeout flag for provider extras.
// A zero duration falls back to 60s, matching the existing observation cmds.
func extraTimeout() (time.Duration, error) {
	dur, err := parseTimeoutFlag(timeout)
	if err != nil {
		return 0, err
	}
	if dur == 0 {
		dur = 60 * time.Second
	}
	return dur, nil
}

// withProviderSession runs fn against a resolved provider session: timeout,
// credential overlay, and a required host. Command-specific flag checks
// belong in the caller so they fail before a missing-host error.
func withProviderSession(provider string, fn func(ctx context.Context, opts providers.ImportOptions) error) error {
	dur, err := extraTimeout()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), dur)
	defer cancel()
	opts := providerImportOptions(provider)
	if err := requireProviderHost(opts, provider); err != nil {
		return err
	}
	return fn(ctx, opts)
}

func toOpnsenseOptions(opts providers.ImportOptions) service.OpnsenseOptions {
	return service.OpnsenseOptions{
		Host:          opts.Host,
		APIKey:        opts.ClientID,
		APISecret:     opts.ClientSecret,
		SkipTLSVerify: opts.SkipTLSVerify,
		CACertPath:    opts.CACertPath,
	}
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func printPlan(v any, action string) error {
	if jsonOutput {
		return printJSON(v)
	}
	fmt.Printf("Plan: %s\n", action)
	return nil
}

func printApply(v any, outcome string, dryRun bool) error {
	if jsonOutput {
		return printJSON(v)
	}
	if dryRun {
		fmt.Printf("Dry-run: %s\n", outcome)
		return nil
	}
	fmt.Printf("Applied: %s\n", outcome)
	return nil
}

func addDryRunFlag(cmd *cobra.Command, dryRun *bool) {
	cmd.Flags().BoolVar(dryRun, "dry-run", true, "Preview without mutating (default true)")
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseProtocolList(s string) ([]int, error) {
	parts := splitCSV(s)
	if len(parts) == 0 {
		return nil, nil
	}
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("protocols must be a comma-separated list of protocol numbers, got %q", s)
		}
		out = append(out, n)
	}
	return out, nil
}

func requireNonEmpty(flag, value string) error {
	if value == "" {
		return fmt.Errorf("--%s is required", flag)
	}
	return nil
}
