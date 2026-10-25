package logger

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"

	"go.opentelemetry.io/otel"
	otlploghttp "go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	otlpmetrichttp "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	otlptracehttp "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// OTLP observability (#137): logs, traces, and metrics exported over
// OTLP/HTTP through the same pipeline as the rotating file log — one
// config surface, one PII-safe resource, one process-wide Shutdown.
//
// Configuration (environment):
//
//	NYX_OTLP_ENDPOINT   OTLP/HTTP base URL (e.g. http://localhost:4318).
//	                    An explicit http(s):// URL is required: the scheme
//	                    picks plain HTTP vs TLS. Empty (the default) keeps
//	                    OTLP disabled — the file log is the whole pipeline.
//	NYX_OTLP_HEADERS    Optional comma-separated key=value pairs sent as
//	                    headers on every export (e.g. auth tokens). Each
//	                    pair splits on the first '='.
//
// Emitted signals (all carry the PII-safe resource: service.name=nyx,
// service.version, os.type, host.arch — never host name or IP):
//
//	logs    the same records as the rotating file log
//	traces  one span per audit run plus one span per assertion
//	metrics nyx_audit_assertions_total{type,status} and
//	        nyx_audit_run_duration_ms
//
// Records carry no live spec values by construction (the same contract as
// the file log, docs/naming.md), so the exported payloads stay secret-free
// by default.

// otlpConfig is the parsed OTLP configuration surface.
type otlpConfig struct {
	Enabled  bool
	Host     string // host:port for the OTLP/HTTP exporters (no scheme)
	Insecure bool   // http:// endpoints export without TLS
	Headers  map[string]string
}

// parseOTLPConfig reads NYX_OTLP_ENDPOINT and NYX_OTLP_HEADERS. An empty
// endpoint disables OTLP; a non-empty one must be an explicit http(s)://
// base URL so the scheme (not a guess) decides TLS.
func parseOTLPConfig() (otlpConfig, error) {
	cfg := otlpConfig{Headers: map[string]string{}}
	endpoint := strings.TrimSpace(os.Getenv("NYX_OTLP_ENDPOINT"))
	if endpoint == "" {
		return cfg, nil
	}
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return otlpConfig{}, fmt.Errorf("NYX_OTLP_ENDPOINT must be an http(s):// base URL, got %q", endpoint)
	}
	cfg.Enabled = true
	cfg.Host = u.Host
	cfg.Insecure = u.Scheme == "http"
	for _, pair := range strings.Split(os.Getenv("NYX_OTLP_HEADERS"), ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		k, v, ok := strings.Cut(pair, "=")
		if !ok || k == "" {
			return otlpConfig{}, fmt.Errorf("NYX_OTLP_HEADERS entries must be key=value, got %q", pair)
		}
		cfg.Headers[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return cfg, nil
}

// otlpTelemetry owns the trace and meter providers (plus the OTLP log
// exporter) for one process. Shutdown is idempotent.
type otlpTelemetry struct {
	tracerProvider *sdktrace.TracerProvider
	meterProvider  *sdkmetric.MeterProvider
	logExporter    sdklog.Exporter
	shutdownOnce   sync.Once
}

// exporterHeaders applies the configured NYX_OTLP_HEADERS to an exporter
// option list. The option types differ per exporter, so the caller passes
// its own WithHeaders function.
func exporterHeaders[T any](cfg otlpConfig, withHeaders func(...map[string]string) T, opts []T) []T {
	if len(cfg.Headers) > 0 {
		opts = append(opts, withHeaders(cfg.Headers))
	}
	return opts
}

// newOTLPTelemetry builds the OTLP pipelines for cfg: OTLP/HTTP exporters
// for logs, traces, and metrics sharing one PII-safe resource.
func newOTLPTelemetry(cfg otlpConfig) (*otlpTelemetry, error) {
	res := newSafeResource()

	traceOpts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(cfg.Host),
	}
	if cfg.Insecure {
		traceOpts = append(traceOpts, otlptracehttp.WithInsecure())
	}
	if len(cfg.Headers) > 0 {
		traceOpts = append(traceOpts, otlptracehttp.WithHeaders(cfg.Headers))
	}
	traceExp, err := otlptracehttp.New(context.Background(), traceOpts...)
	if err != nil {
		return nil, fmt.Errorf("building OTLP trace exporter: %w", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithBatcher(traceExp),
	)

	metricOpts := []otlpmetrichttp.Option{
		otlpmetrichttp.WithEndpoint(cfg.Host),
	}
	if cfg.Insecure {
		metricOpts = append(metricOpts, otlpmetrichttp.WithInsecure())
	}
	if len(cfg.Headers) > 0 {
		metricOpts = append(metricOpts, otlpmetrichttp.WithHeaders(cfg.Headers))
	}
	metricExp, err := otlpmetrichttp.New(context.Background(), metricOpts...)
	if err != nil {
		_ = tp.Shutdown(context.Background())
		return nil, fmt.Errorf("building OTLP metric exporter: %w", err)
	}
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExp)),
	)

	logOpts := []otlploghttp.Option{
		otlploghttp.WithEndpoint(cfg.Host),
	}
	if cfg.Insecure {
		logOpts = append(logOpts, otlploghttp.WithInsecure())
	}
	if len(cfg.Headers) > 0 {
		logOpts = append(logOpts, otlploghttp.WithHeaders(cfg.Headers))
	}
	logExp, err := otlploghttp.New(context.Background(), logOpts...)
	if err != nil {
		_ = tp.Shutdown(context.Background())
		_ = mp.Shutdown(context.Background())
		return nil, fmt.Errorf("building OTLP log exporter: %w", err)
	}

	return &otlpTelemetry{
		tracerProvider: tp,
		meterProvider:  mp,
		logExporter:    logExp,
	}, nil
}

// Shutdown flushes and closes every OTLP pipeline. Idempotent.
func (t *otlpTelemetry) Shutdown(ctx context.Context) error {
	var err error
	t.shutdownOnce.Do(func() {
		err = t.tracerProvider.Shutdown(ctx)
		if merr := t.meterProvider.Shutdown(ctx); merr != nil && err == nil {
			err = merr
		}
		if lerr := t.logExporter.Shutdown(ctx); lerr != nil && err == nil {
			err = lerr
		}
	})
	return err
}

// registeredTelemetry tracks the process's OTLP pipelines so the single
// deferred Shutdown() flushes them alongside the log providers.
var (
	telemetryMu   sync.Mutex
	telemetryOnce = map[*otlpTelemetry]func(){}
	otlpActive    bool
	telemetryInst *otlpTelemetry
)

// InitTelemetry wires OTLP observability for the process when
// NYX_OTLP_ENDPOINT is configured: it creates the trace and meter
// providers, registers the OTLP log exporter for the log pipeline, sets
// the global OTel providers, and hands everything to Shutdown. Disabled
// (the default) it is a no-op — the file log pipeline alone remains.
// Best-effort: a telemetry failure never fails a nyx command; it logs to
// stderr and continues without OTLP.
func InitTelemetry() error {
	cfg, err := parseOTLPConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "nyx: ignoring OTLP configuration: %v\n", err)
		return nil
	}
	if !cfg.Enabled {
		return nil
	}
	tel, err := newOTLPTelemetry(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "nyx: OTLP telemetry unavailable: %v\n", err)
		return nil
	}
	telemetryMu.Lock()
	telemetryInst = tel
	otlpActive = true
	telemetryMu.Unlock()
	otelSetGlobals(tel)
	return nil
}

// OTLPEnabled reports whether OTLP telemetry was initialized for this
// process (tests and callers use it to assert the disabled default).
func OTLPEnabled() bool {
	telemetryMu.Lock()
	defer telemetryMu.Unlock()
	return otlpActive
}

// telemetryShutdown flushes the OTLP pipelines if any were created. Called
// by the package Shutdown, after the log providers.
func telemetryShutdown() {
	telemetryMu.Lock()
	tel := telemetryInst
	telemetryInst = nil
	otlpActive = false
	telemetryMu.Unlock()
	if tel != nil {
		_ = tel.Shutdown(context.Background())
	}
}

// TelemetryTracerProvider returns the process tracer provider (nil when
// OTLP is disabled) for callers that build their own spans.
func TelemetryTracerProvider() *sdktrace.TracerProvider {
	telemetryMu.Lock()
	defer telemetryMu.Unlock()
	if telemetryInst == nil {
		return nil
	}
	return telemetryInst.tracerProvider
}

// TelemetryMeterProvider returns the process meter provider (nil when
// OTLP is disabled).
func TelemetryMeterProvider() *sdkmetric.MeterProvider {
	telemetryMu.Lock()
	defer telemetryMu.Unlock()
	if telemetryInst == nil {
		return nil
	}
	return telemetryInst.meterProvider
}

// TelemetryLogExporter returns the OTLP log exporter (nil when disabled)
// for the log pipeline's batch processor.
func TelemetryLogExporter() sdklog.Exporter {
	telemetryMu.Lock()
	defer telemetryMu.Unlock()
	if telemetryInst == nil {
		return nil
	}
	return telemetryInst.logExporter
}

// otelSetGlobals installs the telemetry's providers as the process-wide
// OTel globals so engine instrumentation through otel.Tracer/otel.Meter
// flows to the configured collector. In tests this is the only place the
// globals are touched, so a process running with OTLP disabled keeps the
// default no-op providers.
func otelSetGlobals(tel *otlpTelemetry) {
	otel.SetTracerProvider(tel.tracerProvider)
	otel.SetMeterProvider(tel.meterProvider)
}
