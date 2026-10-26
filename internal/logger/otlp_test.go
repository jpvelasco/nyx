package logger

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"log/slog"
	"path/filepath"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

// parseOTLPConfig carries the whole OTLP configuration surface (#137):
// NYX_OTLP_ENDPOINT (base URL; empty = disabled, the default) and
// NYX_OTLP_HEADERS (optional comma-separated key=value pairs).

func TestParseOTLPConfig_DisabledByDefault(t *testing.T) {
	t.Setenv("NYX_OTLP_ENDPOINT", "")
	t.Setenv("NYX_OTLP_HEADERS", "")
	cfg, err := parseOTLPConfig()
	if err != nil {
		t.Fatalf("parseOTLPConfig: %v", err)
	}
	if cfg.Enabled {
		t.Error("OTLP must be disabled when NYX_OTLP_ENDPOINT is unset")
	}
}

func TestParseOTLPConfig_HTTPAndHTTPS(t *testing.T) {
	cases := []struct {
		endpoint   string
		wantHost   string
		wantSecure bool
	}{
		{"http://localhost:4318", "localhost:4318", false},
		{"https://collector.example:4318", "collector.example:4318", true},
		{"http://127.0.0.1:4318/", "127.0.0.1:4318", false},
	}
	for _, tc := range cases {
		t.Run(tc.endpoint, func(t *testing.T) {
			t.Setenv("NYX_OTLP_ENDPOINT", tc.endpoint)
			cfg, err := parseOTLPConfig()
			if err != nil {
				t.Fatalf("parseOTLPConfig: %v", err)
			}
			if !cfg.Enabled {
				t.Fatal("configured endpoint must enable OTLP")
			}
			if cfg.Host != tc.wantHost {
				t.Errorf("host = %q, want %q", cfg.Host, tc.wantHost)
			}
			if cfg.Insecure != !tc.wantSecure {
				t.Errorf("insecure = %v, want %v", cfg.Insecure, !tc.wantSecure)
			}
		})
	}
}

func TestParseOTLPConfig_RejectsNonHTTPEndpoints(t *testing.T) {
	for _, bad := range []string{"localhost:4318", "ftp://x", "collector.example", "http://"} {
		t.Run(bad, func(t *testing.T) {
			t.Setenv("NYX_OTLP_ENDPOINT", bad)
			if _, err := parseOTLPConfig(); err == nil {
				t.Errorf("endpoint %q must be rejected — an explicit http(s):// base URL is required", bad)
			}
		})
	}
}

func TestParseOTLPConfig_Headers(t *testing.T) {
	t.Setenv("NYX_OTLP_ENDPOINT", "http://localhost:4318")
	t.Setenv("NYX_OTLP_HEADERS", "authorization=Bearer tok,tenant=acme")
	cfg, err := parseOTLPConfig()
	if err != nil {
		t.Fatalf("parseOTLPConfig: %v", err)
	}
	if got := cfg.Headers["authorization"]; got != "Bearer tok" {
		t.Errorf("authorization header = %q", got)
	}
	if got := cfg.Headers["tenant"]; got != "acme" {
		t.Errorf("tenant header = %q", got)
	}
	// A value containing '=' splits on the first one only.
	t.Setenv("NYX_OTLP_HEADERS", "authorization=Basic a=b")
	cfg, err = parseOTLPConfig()
	if err != nil {
		t.Fatalf("parseOTLPConfig: %v", err)
	}
	if got := cfg.Headers["authorization"]; got != "Basic a=b" {
		t.Errorf("header value with '=' = %q, want 'Basic a=b'", got)
	}
}

// TestOTLPTelemetryExportsAllThreeSignals wires a real OTLP sink and
// asserts the telemetry pipeline delivers logs, traces, and metrics when
// configured — the file logging path is untouched (#137).
func TestOTLPTelemetryExportsAllThreeSignals(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	sinkAuth := map[string]bool{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		sinkAuth[r.Header.Get("authorization")] = true
		mu.Unlock()
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	cfg := otlpConfig{Enabled: true, Host: host, Insecure: true,
		Headers: map[string]string{"authorization": "Bearer sink-token"}}
	tel, err := newOTLPTelemetry(cfg)
	if err != nil {
		t.Fatalf("newOTLPTelemetry: %v", err)
	}
	defer tel.Shutdown(context.Background())

	// One log record through the OTLP log exporter.
	var rec sdklog.Record
	rec.SetTimestamp(time.Now())
	rec.SetSeverity(otellog.SeverityInfo)
	rec.SetSeverityText("INFO")
	rec.SetBody(attribute.StringValue("fixture message"))
	if err := tel.logExporter.Export(context.Background(), []sdklog.Record{rec}); err != nil {
		t.Fatalf("log export: %v", err)
	}

	// One span through the tracer provider.
	tracer := tel.tracerProvider.Tracer("nyx")
	ctx, span := tracer.Start(context.Background(), "nyx.test.span")
	span.End()
	if err := tel.tracerProvider.ForceFlush(ctx); err != nil {
		t.Fatalf("trace flush: %v", err)
	}

	// One metric through the meter provider.
	counter, err := tel.meterProvider.Meter("nyx").Int64Counter("nyx_test_total")
	if err != nil {
		t.Fatal(err)
	}
	counter.Add(context.Background(), 1)
	if err := tel.meterProvider.ForceFlush(context.Background()); err != nil {
		t.Fatalf("metric flush: %v", err)
	}

	// Shutdown flushes any batched signal; all three endpoints must have
	// received at least one export POST.
	_ = tel.Shutdown(context.Background())
	mu.Lock()
	defer mu.Unlock()
	seen := map[string]bool{}
	for _, p := range paths {
		seen[p] = true
	}
	for _, want := range []string{"/v1/logs", "/v1/traces", "/v1/metrics"} {
		if !seen[want] {
			t.Errorf("OTLP sink never received %s (got %v)", want, paths)
		}
	}
	if !sinkAuth["Bearer sink-token"] {
		t.Errorf("NYX_OTLP_HEADERS never reached the collector (auth seen: %v)", sinkAuth)
	}
}

// TestInitTelemetryDisabledKeepsDefaults pins the disabled path: without
// an endpoint, no telemetry is created and the global providers are left
// untouched (the file log pipeline is the whole observability path).
func TestInitTelemetryDisabledKeepsDefaults(t *testing.T) {
	t.Setenv("NYX_OTLP_ENDPOINT", "")
	t.Setenv("NYX_OTLP_HEADERS", "")
	if err := InitTelemetry(); err != nil {
		t.Fatalf("InitTelemetry disabled: %v", err)
	}
	if OTLPEnabled() {
		t.Error("OTLPEnabled must report false without an endpoint")
	}
}

// TestTelemetryShutdownIdempotent asserts a second Shutdown is a no-op.
func TestTelemetryShutdownIdempotent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	cfg := otlpConfig{Enabled: true, Host: strings.TrimPrefix(srv.URL, "http://"), Insecure: true}
	tel, err := newOTLPTelemetry(cfg)
	if err != nil {
		t.Fatalf("newOTLPTelemetry: %v", err)
	}
	ctx := context.Background()
	if err := tel.Shutdown(ctx); err != nil {
		t.Fatalf("first shutdown: %v", err)
	}
	if err := tel.Shutdown(ctx); err != nil {
		t.Errorf("second shutdown must be a no-op, got: %v", err)
	}
}

// TestParseOTLPConfig_HeaderValidation pins the header parsing error
// path: a malformed entry is rejected with the offending pair named.
func TestParseOTLPConfig_HeaderValidation(t *testing.T) {
	t.Setenv("NYX_OTLP_ENDPOINT", "http://localhost:4318")
	t.Setenv("NYX_OTLP_HEADERS", "good=yes,noequalssign")
	if _, err := parseOTLPConfig(); err == nil || !strings.Contains(err.Error(), "noequalssign") {
		t.Errorf("malformed header must be rejected naming the pair, got %v", err)
	}
	t.Setenv("NYX_OTLP_HEADERS", "=novalue")
	if _, err := parseOTLPConfig(); err == nil {
		t.Error("an empty header key must be rejected")
	}
}

// TestNewOTLPTelemetrySecureWithHeaders pins the https pipeline
// construction: the exporters build against a secure endpoint with the
// configured headers, and the accessors expose the providers. The
// end-to-end export (including header delivery) is exercised over the
// insecure sink in TestOTLPTelemetryExportsAllThreeSignals — the wire
// behaviors (TLS handshake, header attachment) belong to the exporter.
func TestNewOTLPTelemetrySecureWithHeaders(t *testing.T) {
	cfg := otlpConfig{
		Enabled:  true,
		Host:     "collector.invalid:4318",
		Insecure: false,
		Headers:  map[string]string{"authorization": "Bearer tok"},
	}
	tel, err := newOTLPTelemetry(cfg)
	if err != nil {
		t.Fatalf("newOTLPTelemetry: %v", err)
	}
	if tel.tracerProvider == nil || tel.meterProvider == nil || tel.logExporter == nil {
		t.Fatalf("secure construction must yield all three pipelines, got %+v", tel)
	}
	// Shutdown on an unreachable secure endpoint may surface a flush
	// error — the pipeline still shut down (idempotent second call).
	_ = tel.Shutdown(context.Background())
	if err := tel.Shutdown(context.Background()); err != nil {
		t.Errorf("second shutdown must be a no-op, got: %v", err)
	}
}

// TestTelemetryAccessorsAfterInit pins the accessor behavior around
// InitTelemetry: enabled exposes the providers, disabled returns nil.
func TestTelemetryAccessorsAfterInit(t *testing.T) {
	t.Setenv("NYX_OTLP_ENDPOINT", "")
	t.Setenv("NYX_OTLP_HEADERS", "")
	if err := InitTelemetry(); err != nil {
		t.Fatalf("InitTelemetry disabled: %v", err)
	}
	if TelemetryTracerProvider() != nil || TelemetryMeterProvider() != nil || TelemetryLogExporter() != nil {
		t.Error("disabled telemetry must expose nil accessors")
	}

	// Invalid endpoint: InitTelemetry is best-effort — it reports and
	// continues without failing the command, leaving telemetry off.
	t.Setenv("NYX_OTLP_ENDPOINT", "not-a-url")
	if err := InitTelemetry(); err != nil {
		t.Fatalf("InitTelemetry with an invalid endpoint must not fail the command: %v", err)
	}
	if OTLPEnabled() {
		t.Error("an invalid endpoint must leave telemetry disabled")
	}
}

// TestInitTelemetryEnabled pins the full enabled path: NYX_OTLP_ENDPOINT
// configured ⇒ telemetry initialized, globals set, accessors non-nil, and
// the process-wide Shutdown flushes and clears it.
func TestInitTelemetryEnabled(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("NYX_OTLP_ENDPOINT", srv.URL)
	t.Setenv("NYX_OTLP_HEADERS", "authorization=Bearer init-tok")
	if err := InitTelemetry(); err != nil {
		t.Fatalf("InitTelemetry: %v", err)
	}
	if !OTLPEnabled() {
		t.Fatal("OTLPEnabled must report true after a successful init")
	}
	if TelemetryTracerProvider() == nil || TelemetryMeterProvider() == nil || TelemetryLogExporter() == nil {
		t.Fatal("the enabled accessors must expose the pipelines")
	}

	// A span through the global provider flows to the sink.
	_, span := otel.Tracer("nyx").Start(context.Background(), "init.span")
	span.End()
	Shutdown()

	mu.Lock()
	defer mu.Unlock()
	seen := false
	for _, p := range paths {
		if p == "/v1/traces" {
			seen = true
		}
	}
	if !seen {
		t.Errorf("the global tracer never reached the sink (got %v)", paths)
	}
	if OTLPEnabled() {
		t.Error("Shutdown must clear the enabled state")
	}
}

// TestParseOTLPConfigPreservesBasePath pins the gateway-path behavior:
// a collector gateway base path (e.g. Grafana Cloud's /otlp) survives
// parsing and reaches the signal URLs (#213 review finding: the path
// was silently discarded).
func TestParseOTLPConfigPreservesBasePath(t *testing.T) {
	t.Setenv("NYX_OTLP_ENDPOINT", "https://otlp-gateway.example.net/otlp")
	cfg, err := parseOTLPConfig()
	if err != nil {
		t.Fatalf("parseOTLPConfig: %v", err)
	}
	if cfg.Host != "otlp-gateway.example.net" {
		t.Errorf("host = %q", cfg.Host)
	}
	if cfg.Path != "/otlp" {
		t.Errorf("base path = %q, want /otlp (gateway paths must survive)", cfg.Path)
	}
	if cfg.Insecure {
		t.Error("https must stay secure")
	}
	if got := joinOTLPPath(cfg.Path, "/v1/traces"); got != "/otlp/v1/traces" {
		t.Errorf("trace path = %q, want /otlp/v1/traces", got)
	}
	// The default (no base path) keeps the standard signal paths.
	if got := joinOTLPPath("", "/v1/logs"); got != "/v1/logs" {
		t.Errorf("default log path = %q, want /v1/logs", got)
	}
}

// TestShutdownOrderDrainsLogProvidersBeforeTelemetry pins the drain
// ordering (#213 review finding): the log providers shut down first so
// their OTLP batch processors flush into the still-open exporter; the
// telemetry closes after them. The observable behavior: the sink
// receives a log record exported through a batched provider when the
// process-wide Shutdown runs.
func TestShutdownOrderDrainsLogProvidersBeforeTelemetry(t *testing.T) {
	var mu sync.Mutex
	sawLogs := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if r.URL.Path == "/v1/logs" {
			sawLogs = true
		}
		mu.Unlock()
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("NYX_OTLP_ENDPOINT", srv.URL)
	if err := InitTelemetry(); err != nil {
		t.Fatalf("InitTelemetry: %v", err)
	}
	// The file pipeline attaches the OTLP batch processor to the same
	// records; a logger write buffers into the batch processor.
	sl, err := NewSlog(filepath.Join(t.TempDir(), "nyx.log"), DefaultMaxSize, DefaultMaxFiles, slog.LevelInfo)
	if err != nil {
		t.Fatalf("NewSlog: %v", err)
	}
	sl.Info("drain-order fixture")
	// The process-wide Shutdown must drain the buffered record into the
	// OTLP exporter before closing it.
	Shutdown()

	mu.Lock()
	defer mu.Unlock()
	if !sawLogs {
		t.Error("the batched log record never reached the sink — the exporter closed before the drain")
	}
}
