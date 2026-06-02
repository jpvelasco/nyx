// Package models defines the core data types (Status, CheckResult, AuditReport, RunnerContext, etc.) shared by the audit engine, backends, and report renderers.
package models

import "time"

// Status represents the outcome of a check
type Status string

const (
	// StatusPass indicates the check passed (behavior matched intent).
	StatusPass Status = "pass"
	// StatusFail indicates the check failed (behavior violated intent).
	StatusFail Status = "fail"
	// StatusWarn indicates the check produced a warning (e.g. no hosts discovered but within allowed range).
	StatusWarn Status = "warn"
	// StatusError indicates the check could not be executed (config error, timeout, etc.).
	StatusError Status = "error"
	// StatusSkip indicates the check was skipped.
	StatusSkip Status = "skip"
)

// CheckResult is the normalized result envelope for every check
type CheckResult struct {
	Tool       string                 `json:"tool"`
	CheckType  string                 `json:"check_type"`
	Runner     string                 `json:"runner"`
	Target     string                 `json:"target"`
	Status     Status                 `json:"status"`
	Summary    string                 `json:"summary"`
	Observed   map[string]interface{} `json:"observed"`
	Expected   map[string]interface{} `json:"expected"`
	Violations []string               `json:"violations"`
	Evidence   []string               `json:"evidence"`
	StartedAt  time.Time              `json:"started_at"`
	FinishedAt time.Time              `json:"finished_at"`
	DurationMs int64                  `json:"duration_ms"`
}

// RunnerContext captures where nyx is running relative to the spec networks.
type RunnerContext struct {
	LocalIPs []string `json:"local_ips"`
	Networks []string `json:"networks"` // spec network names this host is inside
}

// AuditReport is the top-level report for a full audit run
type AuditReport struct {
	Audit           string           `json:"audit"`
	Status          Status           `json:"status"`
	Summary         ReportSummary    `json:"summary"`
	Runner          RunnerContext    `json:"runner"`
	Findings        []CheckResult    `json:"findings"`
	Recommendations []Recommendation `json:"recommendations,omitempty"`
}

// Recommendation is an actionable fix for one or more failures.
type Recommendation struct {
	Priority    int      `json:"priority"`
	Category    string   `json:"category"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
	Affected    []string `json:"affected"`
	SpecPatch   string   `json:"spec_patch,omitempty"`
}

// ReportSummary counts results by status
type ReportSummary struct {
	Pass  int `json:"pass"`
	Fail  int `json:"fail"`
	Warn  int `json:"warn"`
	Error int `json:"error"`
	Skip  int `json:"skip"`
}

// NewCheckResult creates a CheckResult with initialized maps/slices and start time
func NewCheckResult(tool, checkType, runner, target string) *CheckResult {
	return &CheckResult{
		Tool:       tool,
		CheckType:  checkType,
		Runner:     runner,
		Target:     target,
		Observed:   make(map[string]interface{}),
		Expected:   make(map[string]interface{}),
		Violations: []string{},
		Evidence:   []string{},
		StartedAt:  time.Now(),
	}
}

// Finish sets the end time and duration
func (r *CheckResult) Finish() {
	r.FinishedAt = time.Now()
	r.DurationMs = r.FinishedAt.Sub(r.StartedAt).Milliseconds()
}

// ComputeOverallStatus determines the worst status from a list of results
func ComputeOverallStatus(results []CheckResult) Status {
	hasWarn := false
	hasFail := false
	hasError := false
	for _, r := range results {
		switch r.Status {
		case StatusError:
			hasError = true
		case StatusFail:
			hasFail = true
		case StatusWarn:
			hasWarn = true
		}
	}
	if hasError {
		return StatusError
	}
	if hasFail {
		return StatusFail
	}
	if hasWarn {
		return StatusWarn
	}
	return StatusPass
}

// Tally counts results by status
func Tally(results []CheckResult) ReportSummary {
	s := ReportSummary{}
	for _, r := range results {
		switch r.Status {
		case StatusPass:
			s.Pass++
		case StatusFail:
			s.Fail++
		case StatusWarn:
			s.Warn++
		case StatusError:
			s.Error++
		case StatusSkip:
			s.Skip++
		}
	}
	return s
}
