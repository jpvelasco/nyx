package audit

import (
	"context"
	"fmt"
	"strings"

	"github.com/jpvelasco/nyx/internal/backends/nmap"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
)

func (e *Engine) runPortCheck(ctx context.Context, a intent.Assertion) (*models.CheckResult, error) {
	protocol := a.Protocol
	if protocol == "" {
		protocol = "tcp"
	}
	scanMode := nmap.ScanMode(a.ScanMode)
	if a.ScanMode == "" {
		scanMode = nmap.ScanModePolite
	}
	opts := nmap.ScanOptionsForMode(scanMode)

	result, err := e.Backend.PortScan(ctx, a.Target, a.Ports, protocol, opts)
	if err != nil {
		return nil, fmt.Errorf("port scan failed: %w", err)
	}

	// Evaluate pass/fail: all ports must match expect.
	// The nmap backend scans with --open, so ports absent from the output
	// are reported as "filtered" — nmap cannot distinguish closed from
	// filtered there. The meaningful verdict is therefore open vs not-open:
	// expect "closed" passes whenever the port is NOT open.
	expectOpen := a.Expect == "open"
	var violations []string
	if portData, ok := result.Observed["ports"]; ok {
		if ports, ok := portData.([]interface{}); ok {
			for _, p := range ports {
				if pm, ok := p.(map[string]interface{}); ok {
					state, _ := pm["state"].(string)
					port, _ := pm["port"].(float64)
					isOpen := state == "open"
					if expectOpen && !isOpen {
						violations = append(violations, fmt.Sprintf("port %.0f: expected open, got %s", port, state))
					} else if !expectOpen && isOpen {
						violations = append(violations, fmt.Sprintf("port %.0f: expected closed, got open", port))
					}
				}
			}
		}
	}
	if len(violations) > 0 {
		result.Status = models.StatusFail
		result.Violations = violations
		result.Summary = fmt.Sprintf("port check failed on %s: %s", a.Target, strings.Join(violations, "; "))
	}
	result.Expected["expect"] = a.Expect
	result.Expected["ports"] = a.Ports
	return result, nil
}
