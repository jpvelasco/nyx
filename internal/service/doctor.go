package service

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jpvelasco/nyx/internal/backends/nmap"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/probe"
)

// NmapCheck returns a CheckResult for whether nmap is available.
func NmapCheck() *models.CheckResult {
	result := models.NewCheckResult("doctor", "nmap_installed", "local", "nmap")
	if !nmap.Available() {
		result.Status = models.StatusFail
		result.Summary = "nmap is not installed or not in PATH"
		result.Finish()
		return result
	}
	result.Status = models.StatusPass
	result.Summary = "nmap is available"
	result.Finish()
	return result
}

// SpecFileCheck returns a CheckResult for whether the spec file is readable.
func SpecFileCheck(path string) *models.CheckResult {
	result := models.NewCheckResult("doctor", "spec_file", "local", path)
	// #nosec G304 — path from spec, not user-controlled
	data, err := os.ReadFile(path)
	if err != nil {
		result.Status = models.StatusFail
		result.Summary = fmt.Sprintf("cannot read spec file: %v", err)
		result.Finish()
		return result
	}
	result.Status = models.StatusPass
	result.Summary = fmt.Sprintf("spec file readable (%d bytes)", len(data))
	result.Finish()
	return result
}

// ProbeChecks returns a doctor-style check per probe declared in the spec
// file: SSH reachability + authentication via a read-only handshake. It
// returns nil when the spec cannot be loaded — the caller's file/validity
// checks already surface that.
func ProbeChecks(path string) []*models.CheckResult {
	spec, err := intent.LoadSpec(path)
	if err != nil {
		return nil
	}
	var checks []*models.CheckResult
	for _, p := range spec.Probes {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		checks = append(checks, probe.DiagnosticCheck(ctx, probe.FromSpec(p)))
		cancel()
	}
	return checks
}

// SpecValidCheck returns a CheckResult for whether the spec file is valid.
func SpecValidCheck(path string) *models.CheckResult {
	result := models.NewCheckResult("doctor", "spec_valid", "local", path)
	// #nosec G304 — path from spec, not user-controlled
	data, err := os.ReadFile(path)
	if err != nil {
		result.Status = models.StatusFail
		result.Summary = fmt.Sprintf("cannot read spec file: %v", err)
		result.Finish()
		return result
	}
	if _, err := intent.ParseSpec(data); err != nil {
		result.Status = models.StatusFail
		result.Summary = fmt.Sprintf("spec invalid: %v", err)
	} else {
		result.Status = models.StatusPass
		result.Summary = "spec is valid"
	}
	result.Finish()
	return result
}
