package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/logger"
)

// capturingLogHandler records slog messages (with their static attrs) into
// a shared sink for assertions. WithAttrs shares the sink, so records made
// through a derived logger are captured too.
type capturingLogHandler struct {
	sink  *[]string
	attrs []slog.Attr
}

func newCapturingLogHandler() (*capturingLogHandler, *[]string) {
	var lines []string
	return &capturingLogHandler{sink: &lines}, &lines
}

func (h *capturingLogHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *capturingLogHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.WriteString(r.Message)
	for _, a := range h.attrs {
		b.WriteString(" ")
		b.WriteString(a.Key)
		b.WriteString("=")
		b.WriteString(a.Value.String())
	}
	r.Attrs(func(a slog.Attr) bool {
		b.WriteString(" ")
		b.WriteString(a.Key)
		b.WriteString("=")
		b.WriteString(a.Value.String())
		return true
	})
	*h.sink = append(*h.sink, b.String())
	return nil
}

func (h *capturingLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &capturingLogHandler{sink: h.sink, attrs: append(h.attrs, attrs...)}
}

func (h *capturingLogHandler) WithGroup(_ string) slog.Handler { return h }

// TestToolCallLogsToLoggerAndKeepsStdoutRPCClean asserts that a tools/call
// emits a log record (with a trace_id) while the stdout RPC channel carries
// only the JSON-RPC response — never log data.
func TestToolCallLogsToLoggerAndKeepsStdoutRPCClean(t *testing.T) {
	handler, cap := newCapturingLogHandler()
	server := NewServerWithLogger(slog.New(handler))
	server.initialized = true
	server.reader = &bytes.Buffer{}
	server.writer = &bytes.Buffer{}

	res := server.handleToolCall(context.Background(), &jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Params:  json.RawMessage(`{"name":"provider_list","arguments":{}}`),
	})
	if res.Error != nil {
		t.Fatalf("tools/call failed: %+v", res.Error)
	}
	// writeResponse is how Serve emits responses to the RPC channel.
	server.writeResponse(res)

	found := false
	for _, line := range *cap {
		if strings.Contains(line, "tool_call") && strings.Contains(line, "trace_id=") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a tool_call log record with trace_id, got: %v", *cap)
	}

	out := server.writer.(*bytes.Buffer).String()
	if !strings.Contains(out, `"jsonrpc"`) {
		t.Fatalf("stdout missing JSON-RPC response: %q", out)
	}
	for _, leak := range []string{"trace_id", `"cmd"`, `"level"`, `"ts"`} {
		if strings.Contains(out, leak) {
			t.Errorf("stdout RPC channel must stay clean of log data, found %s in: %q", leak, out)
		}
	}
}

// TestServeToolCallThenShutdownCoversMCPExit covers the MCP process-exit
// path end to end: a serve loop that EOFs returns cleanly, and the shared
// pipeline's Shutdown (fired by the deferred logger.Shutdown() in
// cli.Execute) has flushed the final record to the file.
func TestServeToolCallThenShutdownCoversMCPExit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nyx.log")
	sl, err := logger.NewSlog(path, 1024*1024, 3, slog.LevelInfo)
	if err != nil {
		t.Fatalf("NewSlog: %v", err)
	}
	server := NewServerWithLogger(sl)
	server.reader = strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}
{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"provider_list","arguments":{}}}
`)
	server.writer = &bytes.Buffer{}

	if err := server.Serve(context.Background()); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	// Close this pipeline (the deferred logger.Shutdown() in cli.Execute()
	// does this for every pipeline at process exit; closing one directly
	// keeps this test isolated from sibling tests).
	logger.CloseSlog(sl)

	data, err := os.ReadFile(path) // nosemgrep: go_filesystem_rule-fileread
	if err != nil {
		t.Fatalf("reading log: %v", err)
	}
	text := string(data)
	for _, want := range []string{`"msg":"tool_call"`, `"cmd":"mcp"`, `"tool":"provider_list"`, `"trace_id":`} {
		if !strings.Contains(text, want) {
			t.Errorf("final record missing %s; got: %s", want, text)
		}
	}
}
