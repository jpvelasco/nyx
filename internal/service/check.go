// Package service provides shared check operations used by both the CLI and the MCP server.
package service

import (
	"context"
	"fmt"

	"github.com/jpvelasco/nyx/internal/backends"
	"github.com/jpvelasco/nyx/internal/backends/system"
	"github.com/jpvelasco/nyx/internal/models"
)

// CheckService wraps the backend and provides common check operations
// used by both the CLI and MCP server.
type CheckService struct {
	Backend backends.Backend
}

// NewCheckService creates a CheckService with the default backend.
func NewCheckService() *CheckService {
	return &CheckService{Backend: backends.NewDefaultBackend()}
}

// CheckRoute returns the routing path to a target IP.
func (s *CheckService) CheckRoute(ctx context.Context, target string) *models.CheckResult {
	result := models.NewCheckResult("system", "route_check", "local", target)
	route, err := s.Backend.GetRouteToTarget(ctx, target)
	if err != nil {
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("failed to get route to %s: %v", target, err)
		result.Finish()
		return result
	}
	result.Observed["gateway"] = route.Gateway
	result.Observed["device"] = route.Device
	result.Status = models.StatusPass
	result.Summary = fmt.Sprintf("route to %s via %s dev %s", target, route.Gateway, route.Device)
	result.Finish()
	return result
}

// CheckVPN checks if traffic to a target routes through a VPN tunnel.
func (s *CheckService) CheckVPN(ctx context.Context, target string) *models.CheckResult {
	result := models.NewCheckResult("system", "vpn_route", "local", target)
	route, err := s.Backend.GetRouteToTarget(ctx, target)
	if err != nil {
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("failed to get route to %s: %v", target, err)
		result.Finish()
		return result
	}
	result.Observed["device"] = route.Device
	result.Observed["gateway"] = route.Gateway
	isVPN, _ := s.Backend.CheckVPNInterface(ctx, route.Device)
	result.Observed["via_tunnel"] = isVPN
	if isVPN {
		result.Status = models.StatusPass
		result.Summary = fmt.Sprintf("%s routes via tunnel (%s)", target, route.Device)
	} else {
		result.Status = models.StatusWarn
		result.Summary = fmt.Sprintf("%s routes via %s (not a tunnel interface)", target, route.Device)
	}
	result.Finish()
	return result
}

// Ping returns reachability status for a target.
func (s *CheckService) Ping(ctx context.Context, target string) *models.CheckResult {
	result := models.NewCheckResult("system", "ping", "local", target)
	pingResult, err := s.Backend.Ping(ctx, target)
	if err != nil {
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("ping failed: %v", err)
		result.Finish()
		return result
	}
	result.Observed["reachable"] = pingResult.Reachable
	if pingResult.Reachable {
		result.Status = models.StatusPass
		result.Summary = fmt.Sprintf("%s is reachable", target)
	} else {
		result.Status = models.StatusFail
		result.Summary = fmt.Sprintf("%s is not reachable", target)
	}
	result.Finish()
	return result
}

// GetInterfaces returns all network interfaces.
func (s *CheckService) GetInterfaces(ctx context.Context) ([]system.Interface, error) {
	return s.Backend.GetInterfaces(ctx)
}
