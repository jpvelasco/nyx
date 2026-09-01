package logger

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

func TestRecordShape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nyx.log")
	sl, err := NewSlog(path, 5*1024*1024, 3, slog.LevelDebug)
	if err != nil {
		t.Fatalf("NewSlog: %v", err)
	}
	sl = sl.With("trace_id", "deadbeef", "cmd", "omada")
	sl.Info("audit", "status", "pass", "count", 3)
	sl.Warn("virtual ack", "network", "iot")
	sl.Error("boom", "err", testErr)
	sl = sl.With(slog.Group("grp", slog.String("k", "v")))
	sl.Info("grouped", "x", 1)
	CloseSlog(sl)
	CloseSlog(sl) // second close must be a no-op

	data, err := os.ReadFile(path) // nosemgrep: go_filesystem_rule-fileread
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	text := string(data)
	for _, want := range []string{
		`"trace_id":"deadbeef"`, `"cmd":"omada"`, `"msg":"audit"`, `"status":"pass"`,
		`"level":"info"`, `"level":"warn"`, `"level":"error"`,
		`"error":"something failed"`,
		`"grp.k":"v"`, `"service.name":"nyx"`,
		`"os.type":"` + runtime.GOOS + `"`, `"host.arch":"` + runtime.GOARCH + `"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("log missing %s; got:\n%s", want, text)
		}
	}
	// "version" appears exactly once per line (service.version is folded in).
	if n := strings.Count(text, `"version":`); n != 4 {
		t.Errorf("expected one version field per line, got %d in:\n%s", n, text)
	}
	if strings.Contains(text, "exception") {
		t.Errorf("exception.* attributes must not leak into the line: %s", text)
	}
}

// TestShutdownFlushesAndIsIdempotent covers the process-lifecycle contract:
// Shutdown flushes and closes every registered pipeline, a second Shutdown
// is a safe no-op, and records emitted before Shutdown survive in the file.
func TestShutdownFlushesAndIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nyx.log")
	sl, err := NewSlog(path, 1024*1024, 3, slog.LevelInfo)
	if err != nil {
		t.Fatalf("NewSlog: %v", err)
	}
	sl.Info("final", "run", 1)

	Shutdown()
	Shutdown() // second call must be a no-op

	data, err := os.ReadFile(path) // nosemgrep: go_filesystem_rule-fileread
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !strings.Contains(string(data), `"msg":"final"`) {
		t.Errorf("record lost across Shutdown; got:\n%s", data)
	}
}

// TestFileExporterShutdown verifies the sdklog.Exporter contract: after
// Shutdown, Export reports ErrExporterShutdown and records are dropped.
func TestFileExporterShutdown(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nyx.log")
	e, err := newFileExporter(path, 1024, 3)
	if err != nil {
		t.Fatalf("newFileExporter: %v", err)
	}
	if err := e.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := e.Shutdown(context.Background()); err != nil { // idempotent
		t.Fatalf("second Shutdown: %v", err)
	}
	var r sdklog.Record
	r.SetBody(attribute.StringValue("after shutdown"))
	if err := e.Export(context.Background(), []sdklog.Record{r}); err != sdklog.ErrExporterShutdown {
		t.Errorf("Export after Shutdown = %v, want ErrExporterShutdown", err)
	}
}

var testErr = errorValue("something failed")

type errorValue string

func (e errorValue) Error() string { return string(e) }

// TestLevelTextFallback covers the numeric-severity fallback in levelText:
// the otelslog bridge always sets SeverityText, but a hand-built record that
// omits it must still yield the lowercased level from the numeric severity.
func TestLevelTextFallback(t *testing.T) {
	var r sdklog.Record
	r.SetSeverity(log.SeverityWarn)
	if got := levelText(&r); got != "warn" {
		t.Errorf("levelText without SeverityText = %q, want %q", got, "warn")
	}
}

// TestFlattenValueSlice covers the SLICE branch of flattenValue: a slice
// attribute becomes a flat JSON array of its leaves (never a nested map).
// attribute.SliceValue produces a true SLICE type (mixed elements); the
// typed constructors like StringSliceValue are their own STRINGSLICE type
// and take the scalar default branch.
func TestFlattenValueSlice(t *testing.T) {
	out := map[string]any{}
	flattenValue("tags", attribute.SliceValue(attribute.StringValue("a"), attribute.IntValue(1)), out)
	got, ok := out["tags"].([]any)
	if !ok {
		t.Fatalf("flattenValue slice = %T, want []any", out["tags"])
	}
	if len(got) != 2 {
		t.Fatalf("flattenValue slice len = %d, want 2", len(got))
	}
	// Leaf scalars surface as their native Go types (string / int64).
	if s, ok := got[0].(string); !ok || s != "a" {
		t.Errorf("leaf 0 = %v (%T), want string \"a\"", got[0], got[0])
	}
	if n, ok := got[1].(int64); !ok || n != 1 {
		t.Errorf("leaf 1 = %v (%T), want int64(1)", got[1], got[1])
	}
}

// TestBridgeHandlerCloseNilProvider is a no-op flush for a handler that was
// not built by NewSlog (e.g. a test's text handler): Close must not panic
// and must not touch any provider.
func TestBridgeHandlerCloseNilProvider(t *testing.T) {
	h := &bridgeHandler{inner: slog.NewTextHandler(io.Discard, nil), level: slog.LevelInfo}
	if err := h.Close(); err != nil {
		t.Errorf("Close on nil provider = %v, want nil", err)
	}
}
