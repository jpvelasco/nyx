package backends

import (
	"context"

	"github.com/jpvelasco/nyx/internal/backends/dns"
	"github.com/jpvelasco/nyx/internal/backends/health"
	"github.com/jpvelasco/nyx/internal/backends/nmap"
	"github.com/jpvelasco/nyx/internal/backends/omada"
	"github.com/jpvelasco/nyx/internal/backends/system"
	"github.com/jpvelasco/nyx/internal/models"
)

// defaultBackend delegates to the package-level functions in each backend package.
type defaultBackend struct{}

// NewDefaultBackend returns a Backend that wraps the existing backend implementations.
func NewDefaultBackend() Backend {
	return &defaultBackend{}
}

// --- Nmap ---

func (d *defaultBackend) Discover(ctx context.Context, cidr string, opts nmap.ScanOptions) (*models.CheckResult, error) {
	return nmap.DiscoverWithOptions(ctx, cidr, opts)
}

func (d *defaultBackend) PortScan(ctx context.Context, target string, ports []int, protocol string, opts nmap.ScanOptions) (*models.CheckResult, error) {
	return nmap.PortScan(ctx, target, ports, protocol, opts)
}

// --- System ---

func (d *defaultBackend) Ping(ctx context.Context, target string) (*system.PingResult, error) {
	return system.Ping(ctx, target)
}

func (d *defaultBackend) GetRouteToTarget(ctx context.Context, target string) (*system.Route, error) {
	return system.GetRouteToTarget(ctx, target)
}

func (d *defaultBackend) GetInterfaces(ctx context.Context) ([]system.Interface, error) {
	return system.GetInterfaces(ctx)
}

func (d *defaultBackend) CheckVPNInterface(ctx context.Context, device string) (bool, error) {
	return system.CheckVPNInterface(ctx, device)
}

// --- DNS ---

func (d *defaultBackend) Resolve(ctx context.Context, query, server string) (*models.CheckResult, error) {
	return dns.Resolve(ctx, query, server)
}

func (d *defaultBackend) ResolveExpect(ctx context.Context, query, server, expectIP string) (*models.CheckResult, error) {
	return dns.ResolveExpect(ctx, query, server, expectIP)
}

func (d *defaultBackend) CheckDNSSEC(ctx context.Context, query, server string) (*models.CheckResult, error) {
	return dns.CheckDNSSEC(ctx, query, server)
}

func (d *defaultBackend) DigAvailable() bool {
	return dns.Available()
}

// --- Health ---

func (d *defaultBackend) PingCheck(ctx context.Context, target string, count int) (*models.CheckResult, *health.PingStats, error) {
	return health.PingCheck(ctx, target, count)
}

func (d *defaultBackend) CheckLatencyAndLoss(ctx context.Context, target string, maxLatencyMs, maxLossPct float64) (*models.CheckResult, error) {
	return health.CheckLatencyAndLoss(ctx, target, maxLatencyMs, maxLossPct)
}

func (d *defaultBackend) ProbeMTU(ctx context.Context, target string, expectedMTU int) (*models.CheckResult, error) {
	return health.ProbeMTU(ctx, target, expectedMTU)
}

// --- Omada ---

func (d *defaultBackend) NewOmadaClient(ctx context.Context, host string, skipTLSVerify bool, caCertPath string) (*omada.Client, error) {
	return omada.NewClient(ctx, host, skipTLSVerify, caCertPath)
}
