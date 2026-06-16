// Package backends defines the Backend interface that abstracts all network
// check operations (nmap, system commands, DNS, health, Omada). This enables
// mocking for tests and plugging in alternative implementations (e.g. batfish).
package backends

import (
	"context"

	"github.com/jpvelasco/nyx/internal/backends/health"
	"github.com/jpvelasco/nyx/internal/backends/nmap"
	"github.com/jpvelasco/nyx/internal/backends/omada"
	"github.com/jpvelasco/nyx/internal/backends/system"
	"github.com/jpvelasco/nyx/internal/models"
)

// Backend abstracts all network check operations used by the audit engine.
type Backend interface {
	// --- Nmap ---
	Discover(ctx context.Context, cidr string, opts nmap.ScanOptions) (*models.CheckResult, error)
	PortScan(ctx context.Context, target string, ports []int, protocol string, opts nmap.ScanOptions) (*models.CheckResult, error)

	// --- System ---
	Ping(ctx context.Context, target string) (*system.PingResult, error)
	GetRouteToTarget(ctx context.Context, target string) (*system.Route, error)
	GetInterfaces(ctx context.Context) ([]system.Interface, error)
	CheckVPNInterface(ctx context.Context, device string) (bool, error)

	// --- DNS ---
	Resolve(ctx context.Context, query, server string) (*models.CheckResult, error)
	ResolveExpect(ctx context.Context, query, server, expectIP string) (*models.CheckResult, error)
	CheckDNSSEC(ctx context.Context, query, server string) (*models.CheckResult, error)
	DigAvailable() bool

	// --- Health ---
	PingCheck(ctx context.Context, target string, count int) (*models.CheckResult, *health.PingStats, error)
	CheckLatencyAndLoss(ctx context.Context, target string, maxLatencyMs, maxLossPct float64) (*models.CheckResult, error)
	ProbeMTU(ctx context.Context, target string, expectedMTU int) (*models.CheckResult, error)

	// --- Omada ---
	NewOmadaClient(ctx context.Context, host string, skipTLSVerify bool, caCertPath string) (*omada.Client, error)
}

// NmapAvailable reports whether nmap is installed on the current system.
type NmapAvailable interface {
	Available() bool
}

// DNSAvailable reports whether dig is installed on the current system.
type DNSAvailable interface {
	DigAvailable() bool
}
