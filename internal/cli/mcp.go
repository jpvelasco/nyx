package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/velasco-jp/netaudit/internal/mcp"
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
	Long: `Start a Model Context Protocol server that exposes netaudit's
read-only tools for AI agents. Default transport is stdio.`,
	Example: `  netaudit mcp serve
  netaudit mcp serve --stdio`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if mcpTransport != "stdio" {
			return fmt.Errorf("only stdio transport is supported in v1")
		}

		server := mcp.NewServer()
		return server.Serve(context.Background())
	},
}

func init() {
	mcpServeCmd.Flags().StringVar(&mcpTransport, "transport", "stdio", "Transport type (stdio)")
	mcpCmd.AddCommand(mcpServeCmd)
}
