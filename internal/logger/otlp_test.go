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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	cfg := otlpConfig{Enabled: true, Host: host, Insecure: true}
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
