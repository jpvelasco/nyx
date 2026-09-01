package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jpvelasco/nyx/internal/mcp"
	"github.com/spf13/cobra"
)

var (
	mcpTransport string
)

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "MCP server commands",
}

var mcpServeCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start MCP server for AI agent integration",
	Long: `Start a Model Context Protocol server that exposes nyx's audit
and vendor tools (including dry-run-default Omada ACL mutation) to AI agents.
Default transport is stdio.`,
	Example: `  nyx mcp serve
  nyx mcp serve --stdio`,
	RunE: func(_ *cobra.Command, _ []string) error {
		if mcpTransport != "stdio" {
			return fmt.Errorf("only stdio transport is supported in v1")
		}

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		// slogLog is the shared OTel-backed file logger (nil only when the
		// pipeline failed to start); the server falls back to the stderr
		// default in that case.
		server := mcp.NewServerWithLogger(slogLog)
		return server.Serve(ctx)
	},
}

func init() {
	mcpServeCmd.Flags().StringVar(&mcpTransport, "transport", "stdio", "Transport type (stdio)")
	mcpCmd.AddCommand(mcpServeCmd)
}
