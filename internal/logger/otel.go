package logger

import (
	"context"
	"encoding/json"
	"log/slog"
	"runtime"
	"strings"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"

	"github.com/jpvelasco/nyx/internal/version"
)

// defaultLogScope is the instrumentation scope attached to every record via
// the otelslog bridge. It is a stable code identity, not PII.
const defaultLogScope = "nyx"

// File rotation defaults shared by the CLI wiring and tests.
const (
	DefaultMaxSize  = 5 * 1024 * 1024 // 5 MB per file
	DefaultMaxFiles = 3
)

// newSafeResource builds a PII-safe OTel resource: identity and platform
// context only. No host.name / host.ip / hostname — a "send us your logs"
// artifact must not identify the machine (docs/naming.md).
func newSafeResource() *resource.Resource {
	return resource.NewSchemaless(
		attribute.String("service.name", "nyx"),
		attribute.String("service.version", version.Version),
		attribute.String("os.type", runtime.GOOS),
		attribute.String("host.arch", runtime.GOARCH),
	)
}

// fileExporter is the sdklog.Exporter that serialises records as one flat
// JSON object per line into a rotatingWriter. Best-effort: it never fails a
// nyx command.
type fileExporter struct {
	mu     sync.Mutex
	closed bool
	res    *resource.Resource
	writer *rotatingWriter
}

func newFileExporter(path string, maxSize int64, maxFiles int) (*fileExporter, error) {
	writer, err := newRotatingWriter(path, maxSize, maxFiles)
	if err != nil {
		return nil, err
	}
	return &fileExporter{res: newSafeResource(), writer: writer}, nil
}

// Export writes each record as one line. The SDK guarantees Export is never
// called concurrently, so per-line marshalling needs no lock of its own.
func (e *fileExporter) Export(ctx context.Context, records []sdklog.Record) error {
	e.mu.Lock()
	closed := e.closed
	e.mu.Unlock()
	if closed {
		return sdklog.ErrExporterShutdown
	}
	for i := range records {
		line, err := e.serialise(&records[i])
		if err != nil {
			continue // best-effort: drop the line, never fail the command
		}
		_, _ = e.writer.Write(line)
	}
	return nil
}

// Shutdown closes the file. It may be called concurrently with itself; a
// second call is a no-op.
func (e *fileExporter) Shutdown(_ context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true
	e.writer.Close()
	return nil
}

// ForceFlush is a no-op: lines are written synchronously in Export.
func (e *fileExporter) ForceFlush(_ context.Context) error { return nil }

// serialise renders one record as a flat JSON object plus a newline. The
// shape is deliberately one level deep (groups are flattened to dotted keys)
// so both a human and the export scrubber can reach every leaf.
func (e *fileExporter) serialise(r *sdklog.Record) ([]byte, error) {
	entry := make(map[string]any, 8+r.AttributesLen()+4)

	if body, ok := r.Body().AsInterface().(string); ok && body != "" {
		entry["msg"] = body
	}
	entry["ts"] = r.Timestamp().UTC().Format("2006-01-02T15:04:05.000Z")
	entry["level"] = levelText(r)

	// cmd names the emitting subsystem; backends set it explicitly, and the
	// default keeps engine/CLI lines categorised too.
	entry["cmd"] = defaultLogScope
	entry["version"] = version.Version

	// The SDK promotes an error-valued slog attribute into the standard
	// exception.* attributes; surface the message as a flat "error" field
	// (the exception.type noise is dropped — it repeats the Go type path).
	r.WalkAttributes(func(kv attribute.KeyValue) bool {
		switch string(kv.Key) {
		case "exception.message":
			if s, ok := kv.Value.AsInterface().(string); ok && s != "" {
				entry["error"] = s
				return true
			}
		case "exception.type":
			return true
		}
		flattenValue(string(kv.Key), kv.Value, entry)
		return true
	})

	for _, kv := range e.res.Attributes() {
		key := string(kv.Key)
		if key == "service.version" { // already present as "version"
			continue
		}
		entry[key] = kv.Value.AsInterface()
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// levelText recovers the original lowercased slog level. The otelslog bridge
// records the slog level verbatim in SeverityText, so prefer that; fall back
// to the numeric severity if it is absent.
func levelText(r *sdklog.Record) string {
	if text := r.SeverityText(); text != "" {
		return strings.ToLower(text)
	}
	return strings.ToLower(log.Severity(r.Severity()).String())
}

// flattenValue records v under key in out. Maps (slog groups) are flattened
// with dotted keys so every line stays one level deep; slices become plain
// JSON arrays of their leaves.
func flattenValue(key string, v attribute.Value, out map[string]any) {
	switch v.Type() {
	case attribute.MAP:
		for _, kv := range v.AsMap() {
			flattenValue(key+"."+string(kv.Key), kv.Value, out)
		}
	case attribute.SLICE:
		vals := v.AsSlice()
		elems := make([]any, len(vals))
		for i := range vals {
			elems[i] = vals[i].AsInterface()
		}
		out[key] = elems
	default:
		out[key] = v.AsInterface()
	}
}

// nyxProvider is the process-wide log pipeline: one OTel LoggerProvider
// (PII-safe resource, simple synchronous processor) feeding the file
// exporter.
type nyxProvider struct {
	provider *sdklog.LoggerProvider
	exporter *fileExporter
}

func newNyxProvider(path string, maxSize int64, maxFiles int) (*nyxProvider, error) {
	exporter, err := newFileExporter(path, maxSize, maxFiles)
	if err != nil {
		return nil, err
	}
	provider := sdklog.NewLoggerProvider(
		sdklog.WithResource(exporter.res),
		sdklog.WithProcessor(sdklog.NewSimpleProcessor(exporter)),
	)
	return &nyxProvider{provider: provider, exporter: exporter}, nil
}

// Shutdown flushes and closes the file. Idempotent — the provider and the
// exporter both treat a second call as a no-op.
func (p *nyxProvider) Shutdown(ctx context.Context) error {
	_ = p.provider.Shutdown(ctx)
	return p.exporter.Shutdown(ctx)
}

// registeredProviders tracks every pipeline created in this process so the
// single deferred Shutdown in cli.Execute() can flush+close them all,
// covering both the CLI and the MCP process exits.
var registeredProviders = new(sync.Map) // *nyxProvider -> struct{}

func registerProvider(p *nyxProvider) { registeredProviders.Store(p, struct{}{}) }

// Shutdown closes every pipeline created in this process. Safe to call more
// than once.
func Shutdown() {
	registeredProviders.Range(func(k, _ any) bool {
		registeredProviders.Delete(k)
		_ = k.(*nyxProvider).Shutdown(context.Background())
		return true
	})
}

// bridgeHandler wraps the otelslog handler with a minimum-level filter (the
// SDK's simple processor accepts every severity, so the level gate has to
// live here) and a Close that flushes the pipeline. Every handler derived
// via WithAttrs/WithGroup shares the same provider, so a logger passed
// around still flushes correctly on Close.
type bridgeHandler struct {
	inner    slog.Handler
	level    slog.Level
	provider *nyxProvider
}

func (h *bridgeHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.level && h.inner.Enabled(context.Background(), l)
}

func (h *bridgeHandler) Handle(ctx context.Context, r slog.Record) error {
	return h.inner.Handle(ctx, r)
}

func (h *bridgeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &bridgeHandler{inner: h.inner.WithAttrs(attrs), level: h.level, provider: h.provider}
}

func (h *bridgeHandler) WithGroup(name string) slog.Handler {
	return &bridgeHandler{inner: h.inner.WithGroup(name), level: h.level, provider: h.provider}
}

// Close flushes and closes the pipeline and unregisters it from
// registeredProviders, so a closed pipeline is not retained for the process
// lifetime (tests create several per package run). slog.Close calls this on a
// logger's handler when the logger itself is closed; it is a no-op for a
// logger whose handler was not created by NewSlog (e.g. tests' text handlers).
func (h *bridgeHandler) Close() error {
	if h.provider == nil {
		return nil
	}
	registeredProviders.Delete(h.provider)
	return h.provider.Shutdown(context.Background())
}
