package service

import (
	"fmt"
	"os"

	"github.com/jpvelasco/nyx/internal/backends/nmap"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
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
