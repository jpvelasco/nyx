package cli

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jpvelasco/nyx/internal/mcp"
	"github.com/spf13/cobra"
)

var (
	mcpTransport string
	mcpBind      string
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

The default transport is stdio (one session per process). The http
transport serves MCP streamable HTTP on a loopback-only listener with a
bearer-token auth: the token comes from NYX_MCP_TOKEN or is generated at
startup and printed once to stderr. Set NYX_OTLP_ENDPOINT to export
telemetry to a collector. See docs/mcp-http.md for the security model.`,
	Example: `  nyx mcp serve
  nyx mcp serve --stdio
  nyx mcp serve --transport http --bind 127.0.0.1:9000`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		switch mcpTransport {
		case "stdio":
			return serveStdio()
		case "http":
			return serveHTTP(cmd.Context())
		default:
			return fmt.Errorf("unsupported transport %q (use stdio or http)", mcpTransport)
		}
	},
}

// serverLog returns the shared OTel-backed logger, falling back to
// the stderr default when the pipeline failed to start so tool-call
// records are not dropped silently.
func serverLog() *slog.Logger {
	if slogLog != nil {
		return slogLog
	}
	return slog.Default()
}

func serveStdio() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	server := mcp.NewServerWithLogger(serverLog())
	return server.Serve(ctx)
}

// serveHTTP runs the MCP streamable-HTTP transport: loopback bind only,
// bearer auth on every request, one Server per session, idle-sweeped.
// serveHTTP runs the MCP streamable-HTTP transport: loopback bind only,
// bearer auth on every request, one Server per session, idle-sweeped.
// The caller's context (cobra's, driven by test harnesses or embedded
// use) shuts the listener down gracefully alongside SIGINT/SIGTERM.
func serveHTTP(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	// SIGINT/SIGTERM cancel the same context so both the signal and the
	// caller can drain the listener.
	signalCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	bind := mcpBind
	if bind == "" {
		bind = "127.0.0.1:0" // ephemeral port, printed once bound
	}
	addr, err := mcp.ValidateBindAddr(bind)
	if err != nil {
		return err
	}

	// The listener token authenticates the MCP endpoint only — it is never
	// an SDN controller credential. NYX_MCP_TOKEN overrides generation;
	// the value is never logged or included in any config snippet.
	token := os.Getenv("NYX_MCP_TOKEN")
	if token == "" {
		token, err = mcp.GenerateListenerToken()
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "nyx mcp: generated listener token (set NYX_MCP_TOKEN to pin it): %s\n", token)
	} else {
		fmt.Fprintln(os.Stderr, "nyx mcp: using listener token from NYX_MCP_TOKEN")
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("binding MCP HTTP listener on %s: %w", addr, err)
	}
	fmt.Fprintf(os.Stderr, "nyx mcp: HTTP transport listening on http://%s (loopback only)\n", listener.Addr().String())

	// The HTTP sessions share the same OTel-backed file logger as
	// stdio, so tool-call records land in the rotating log either way.
	server := mcp.NewHTTPServer(token, serverLog())
	server.StartReaper(ctx)

	// ReadHeaderTimeout bounds slow clients (slowloris); the per-call
	// tool timeout keeps a hung backend from wedging the listener.
	httpServer := &http.Server{
		Handler:           server.Handler(),
		ReadHeaderTimeout: 30 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		errCh <- httpServer.Serve(listener)
	}()

	select {
	case err := <-errCh:
		return err
	case <-signalCtx.Done():
		// Drain in-flight calls and close the listener; no session survives
		// the process.
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		return httpServer.Shutdown(shutdownCtx)
	}
}

func init() {
	mcpServeCmd.Flags().StringVar(&mcpTransport, "transport", "stdio", "Transport type (stdio or http)")
	mcpServeCmd.Flags().StringVar(&mcpBind, "bind", "", "HTTP transport bind address (loopback only, e.g. 127.0.0.1:9000; default 127.0.0.1:0)")
	mcpCmd.AddCommand(mcpServeCmd)
}
