// Package backends provides a mock Backend implementation for unit tests.
package backends

import (
	"context"

	"github.com/jpvelasco/nyx/internal/backends/health"
	"github.com/jpvelasco/nyx/internal/backends/nmap"
	"github.com/jpvelasco/nyx/internal/backends/omada"
	"github.com/jpvelasco/nyx/internal/backends/system"
	"github.com/jpvelasco/nyx/internal/models"
)

// MockBackend implements Backend for unit tests.
// Set the fields before assigning to Engine.Backend.
type MockBackend struct {
	// --- Nmap ---
	DiscoverResult     *models.CheckResult
	DiscoverResultFunc func(cidr string) *models.CheckResult
	DiscoverErr        error
	PortScanResult     *models.CheckResult
	PortScanErr        error

	// --- System ---
	PingResult         *system.PingResult
	PingErr            error
	RouteResult        *system.Route
	RouteErr           error
	InterfacesResult   []system.Interface
	InterfacesErr      error
	VPNInterfaceResult bool
	VPNInterfaceErr    error

	// --- DNS ---
	ResolveResult       *models.CheckResult
	ResolveErr          error
	ResolveExpectResult *models.CheckResult
	ResolveExpectErr    error
	DNSSECResult        *models.CheckResult
	DNSSECErr           error
	DigAvailableResult  bool

	// --- Health ---
	PingCheckResult *models.CheckResult
	PingCheckStats  *health.PingStats
	PingCheckErr    error
	LatencyResult   *models.CheckResult
	LatencyErr      error
	MTUResult       *models.CheckResult
	MTUErr          error

	// --- Omada ---
	OmadaClient *omada.Client
	OmadaErr    error
}

// BackendError is a simple error type for tests.
type BackendError string

func (e BackendError) Error() string { return string(e) }

var _ Backend = (*MockBackend)(nil)

// --- Nmap ---

// Discover returns the pre-configured discovery result.
func (m *MockBackend) Discover(_ context.Context, cidr string, _ nmap.ScanOptions) (*models.CheckResult, error) {
	if m.DiscoverResultFunc != nil {
		return m.DiscoverResultFunc(cidr), m.DiscoverErr
	}
	return m.DiscoverResult, m.DiscoverErr
}

// PortScan returns the pre-configured port scan result.
func (m *MockBackend) PortScan(_ context.Context, _ string, _ []int, _ string, _ nmap.ScanOptions) (*models.CheckResult, error) {
	return m.PortScanResult, m.PortScanErr
}

// --- System ---

// Ping returns the pre-configured ping result.
func (m *MockBackend) Ping(_ context.Context, _ string) (*system.PingResult, error) {
	return m.PingResult, m.PingErr
}

// GetRouteToTarget returns the pre-configured route.
func (m *MockBackend) GetRouteToTarget(_ context.Context, _ string) (*system.Route, error) {
	return m.RouteResult, m.RouteErr
}

// GetInterfaces returns the pre-configured interfaces.
func (m *MockBackend) GetInterfaces(_ context.Context) ([]system.Interface, error) {
	return m.InterfacesResult, m.InterfacesErr
}

// CheckVPNInterface returns the pre-configured VPN interface check result.
func (m *MockBackend) CheckVPNInterface(_ context.Context, _ string) (bool, error) {
	return m.VPNInterfaceResult, m.VPNInterfaceErr
}

// --- DNS ---

// Resolve returns the pre-configured DNS resolve result.
func (m *MockBackend) Resolve(_ context.Context, _ string, _ string) (*models.CheckResult, error) {
	return m.ResolveResult, m.ResolveErr
}

// ResolveExpect returns the pre-configured DNS resolve-with-expect result.
func (m *MockBackend) ResolveExpect(_ context.Context, _ string, _ string, _ string) (*models.CheckResult, error) {
	return m.ResolveExpectResult, m.ResolveExpectErr
}

// CheckDNSSEC returns the pre-configured DNSSEC check result.
func (m *MockBackend) CheckDNSSEC(_ context.Context, _ string, _ string) (*models.CheckResult, error) {
	return m.DNSSECResult, m.DNSSECErr
}

// DigAvailable returns the pre-configured dig availability.
func (m *MockBackend) DigAvailable() bool {
	return m.DigAvailableResult
}

// --- Health ---

// PingCheck returns the pre-configured ping check result.
func (m *MockBackend) PingCheck(_ context.Context, _ string, _ int) (*models.CheckResult, *health.PingStats, error) {
	return m.PingCheckResult, m.PingCheckStats, m.PingCheckErr
}

// CheckLatencyAndLoss returns the pre-configured latency result.
func (m *MockBackend) CheckLatencyAndLoss(_ context.Context, _ string, _, _ float64) (*models.CheckResult, error) {
	return m.LatencyResult, m.LatencyErr
}

// ProbeMTU returns the pre-configured MTU probe result.
func (m *MockBackend) ProbeMTU(_ context.Context, _ string, _ int) (*models.CheckResult, error) {
	return m.MTUResult, m.MTUErr
}

// --- Omada ---

// NewOmadaClient returns the pre-configured Omada client.
func (m *MockBackend) NewOmadaClient(_ context.Context, _ string, _ bool, _ string) (*omada.Client, error) {
	return m.OmadaClient, m.OmadaErr
}
