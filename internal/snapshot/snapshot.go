// Package snapshot handles persisting and comparing full audit reports (snapshots + baseline + drift detection).
package snapshot

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jpvelasco/nyx/internal/models"
)

const (
	defaultMaxSnapshots = 50
	snapshotExt         = ".json"
)

// filenameNow is overridable in tests to make timestamped filenames
// deterministic (collision handling).
var filenameNow = time.Now

// Snapshot wraps an audit report with metadata for persistence.
type Snapshot struct {
	SpecPath        string                  `json:"spec_path"`
	RunAt           time.Time               `json:"run_at"`
	Runner          models.RunnerContext    `json:"runner"`
	Summary         models.ReportSummary    `json:"summary"`
	Status          models.Status           `json:"status"`
	Findings        []models.CheckResult    `json:"findings"`
	Recommendations []models.Recommendation `json:"recommendations,omitempty"`
}

// NewSnapshot creates a Snapshot from an AuditReport and the spec path.
func NewSnapshot(specPath string, report *models.AuditReport) *Snapshot {
	return &Snapshot{
		SpecPath:        specPath,
		RunAt:           time.Now(),
		Runner:          report.Runner,
		Summary:         report.Summary,
		Status:          report.Status,
		Findings:        report.Findings,
		Recommendations: report.Recommendations,
	}
}

// Filename generates a filename for a snapshot. Millisecond granularity keeps
// consecutive audits from colliding; Save additionally retries with a numeric
// suffix if the generated name already exists (see Save).
func Filename() string {
	return fmt.Sprintf("snapshot-%s%s", filenameNow().Format("20060102-150405.000"), snapshotExt)
}

// Dir returns the path to the snapshots directory, creating it if needed.
func Dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	dir := filepath.Join(home, ".nyx", "snapshots")
	//nolint:gosec
	if err := os.MkdirAll(dir, 0700); err != nil { // nosemgrep
		return "", fmt.Errorf("creating snapshot directory: %w", err)
	}
	return dir, nil
}

// Save writes a snapshot to disk and rotates old snapshots.
// Writes use O_EXCL so a concurrent audit producing the same millisecond
// filename cannot silently overwrite the previous run; on collision the name
// is retried with a numeric suffix.
func Save(specPath string, report *models.AuditReport) (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}

	snap := NewSnapshot(specPath, report)
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return "", fmt.Errorf("serializing snapshot: %w", err)
	}

	for attempt := 0; attempt < 100; attempt++ {
		base := strings.TrimSuffix(Filename(), snapshotExt)
		if attempt > 0 {
			base = fmt.Sprintf("%s-%d", base, attempt)
		}
		path := filepath.Join(dir, base+snapshotExt)
		// #nosec G304 — filename is generated from a timestamp, inside the user's snapshot dir
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600) // nosemgrep
		if err != nil {
			if os.IsExist(err) {
				continue // same-millisecond collision — retry with a suffix
			}
			return "", fmt.Errorf("writing snapshot: %w", err)
		}
		if _, err := f.Write(data); err != nil {
			f.Close() // #nosec G104 — best-effort cleanup
			return "", fmt.Errorf("writing snapshot: %w", err)
		}
		if err := f.Close(); err != nil {
			return "", fmt.Errorf("closing snapshot: %w", err)
		}

		// Rotate old snapshots
		rotate(dir, defaultMaxSnapshots)
		return path, nil
	}
	return "", fmt.Errorf("writing snapshot: could not allocate a unique filename")
}

// BaselinePath returns the path to the baseline snapshot file.
func BaselinePath() string {
	dir, err := Dir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "baseline.json")
}

// SetBaseline saves the current snapshot as the baseline.
func SetBaseline(specPath string, report *models.AuditReport) error {
	baselPath := BaselinePath()
	if baselPath == "" {
		return fmt.Errorf("cannot determine baseline path")
	}

	snap := NewSnapshot(specPath, report)
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return fmt.Errorf("serializing baseline: %w", err)
	}

	//nolint:gosec
	return os.WriteFile(baselPath, data, 0600) // nosemgrep
}

// LoadBaseline reads the baseline snapshot.
func LoadBaseline() (*Snapshot, error) {
	baselPath := BaselinePath()
	if baselPath == "" {
		return nil, fmt.Errorf("cannot determine baseline path")
	}

	// #nosec G304 — path is internal, derived from home dir
	data, err := os.ReadFile(baselPath) // nosemgrep
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no baseline snapshot found — run 'nyx snapshot baseline' first")
		}
		return nil, fmt.Errorf("reading baseline: %w", err)
	}

	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("parsing baseline: %w", err)
	}
	return &snap, nil
}

// LoadSnapshot reads a snapshot from the given path.
func LoadSnapshot(path string) (*Snapshot, error) {
	// #nosec G304 — path from spec, not user-controlled
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading snapshot: %w", err)
	}

	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil {
		return nil, fmt.Errorf("parsing snapshot: %w", err)
	}
	return &snap, nil
}

// ListSnapshots returns all snapshot filenames sorted by time (oldest first).
func ListSnapshots() ([]string, error) {
	dir, err := Dir()
	if err != nil {
		return nil, err
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading snapshot directory: %w", err)
	}

	var snaps []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), snapshotExt) && e.Name() != "baseline.json" {
			snaps = append(snaps, e.Name())
		}
	}
	sort.Strings(snaps)
	return snaps, nil
}

// rotate removes the oldest snapshots when the count exceeds maxSnapshots.
func rotate(dir string, maxSnapshots int) {
	snaps, err := ListSnapshots()
	if err != nil {
		return
	}

	for len(snaps) > maxSnapshots {
		oldest := snaps[0]
		snaps = snaps[1:]
		os.Remove(filepath.Join(dir, oldest)) // nosemgrep
		// #nosec G104 — best-effort cleanup
	}
}

// DriftResult represents the result of comparing a newer snapshot against an older one for drift detection.
type DriftResult struct {
	BaselineTime   time.Time            `json:"baseline_time"`
	CurrentTime    time.Time            `json:"current_time"`
	BaselineStatus models.Status        `json:"baseline_status"`
	CurrentStatus  models.Status        `json:"current_status"`
	NewFailures    []models.CheckResult `json:"new_failures,omitempty"`
	NewWarnings    []models.CheckResult `json:"new_warnings,omitempty"`
	FixedFailures  []models.CheckResult `json:"fixed_failures,omitempty"`
	Degraded       []models.CheckResult `json:"degraded,omitempty"`
	Improved       []models.CheckResult `json:"improved,omitempty"`
	Summary        DriftSummary         `json:"summary"`
}

// DriftSummary gives a high-level view of the drift.
type DriftSummary struct {
	BaselinePass  int    `json:"baseline_pass"`
	BaselineFail  int    `json:"baseline_fail"`
	BaselineWarn  int    `json:"baseline_warn"`
	BaselineError int    `json:"baseline_error"`
	CurrentPass   int    `json:"current_pass"`
	CurrentFail   int    `json:"current_fail"`
	CurrentWarn   int    `json:"current_warn"`
	CurrentError  int    `json:"current_error"`
	NetChange     string `json:"net_change"`
}

// ComputeDrift compares two snapshots and returns the drift result.
func ComputeDrift(baseline, current *Snapshot) *DriftResult {
	dr := &DriftResult{
		BaselineTime:   baseline.RunAt,
		CurrentTime:    current.RunAt,
		BaselineStatus: baseline.Status,
		CurrentStatus:  current.Status,
	}

	// Build lookup maps keyed by a composite of check_type + target + summary
	baselineMap := buildLookup(baseline.Findings)
	currentMap := buildLookup(current.Findings)

	// Find new failures/warnings (in current but not in baseline, or status worsened)
	for key, cur := range currentMap {
		base, exists := baselineMap[key]
		if !exists {
			switch cur.Status {
			case models.StatusFail:
				dr.NewFailures = append(dr.NewFailures, cur)
			case models.StatusWarn:
				dr.NewWarnings = append(dr.NewWarnings, cur)
			}
			continue
		}

		// Check for degradation: fail or error states that got worse are
		// surfaceable even when they were already failing (FAIL -> ERROR must
		// not be invisible in the report).
		if statusWorsened(base.Status, cur.Status) &&
			(cur.Status == models.StatusFail || cur.Status == models.StatusError) {
			dr.Degraded = append(dr.Degraded, cur)
		}

		// Track improvements separately. FAIL -> better is reported below as
		// a fixed failure (and skipped here) so a single finding is never
		// listed under both "Fixed" and "Improved".
		if statusImproved(base.Status, cur.Status) && base.Status != models.StatusFail {
			dr.Improved = append(dr.Improved, cur)
		}
	}

	// Find fixed issues (in baseline as fail/warn/error, now better or gone)
	for key, base := range baselineMap {
		cur, exists := currentMap[key]
		if !exists {
			// Gone entirely — count as fixed if it was a failure
			if base.Status == models.StatusFail {
				dr.FixedFailures = append(dr.FixedFailures, base)
			}
			continue
		}
		if base.Status == models.StatusPass {
			continue
		}
		if statusImproved(base.Status, cur.Status) {
			if base.Status == models.StatusFail {
				dr.FixedFailures = append(dr.FixedFailures, base)
			}
		}
	}

	// Build summary
	dr.Summary = DriftSummary{
		BaselinePass:  baseline.Summary.Pass,
		BaselineFail:  baseline.Summary.Fail,
		BaselineWarn:  baseline.Summary.Warn,
		BaselineError: baseline.Summary.Error,
		CurrentPass:   current.Summary.Pass,
		CurrentFail:   current.Summary.Fail,
		CurrentWarn:   current.Summary.Warn,
		CurrentError:  current.Summary.Error,
		NetChange:     computeNetChange(&baseline.Summary, &current.Summary),
	}

	return dr
}

// buildLookup creates a map keyed by check_type + target, with type-specific
// disambiguators to avoid collisions (e.g. two port_check assertions on the
// same target but different ports, or two isolation assertions with the same
// from→to but different expect values).
func buildLookup(findings []models.CheckResult) map[string]models.CheckResult {
	lookup := make(map[string]models.CheckResult)
	for _, f := range findings {
		key := fmt.Sprintf("%s:%s", f.CheckType, f.Target)
		// Disambiguate by expected values when target alone is insufficient
		switch f.CheckType {
		case "port_check":
			if ports, ok := f.Expected["ports"]; ok {
				key = fmt.Sprintf("%s:%v", key, ports)
			}
		case "dns_check":
			if query, ok := f.Expected["query"]; ok {
				key = fmt.Sprintf("%s:%v", key, query)
			}
		case "isolation":
			if expect, ok := f.Expected["expect"]; ok {
				key = fmt.Sprintf("%s:%v", key, expect)
			}
		case "subnet_discovery":
			if hostsMin, ok := f.Expected["expect_hosts_min"]; ok {
				key = fmt.Sprintf("%s:%v", key, hostsMin)
			}
			if hostsMax, ok := f.Expected["expect_hosts_max"]; ok {
				key = fmt.Sprintf("%s:%v", key, hostsMax)
			}
		}
		lookup[key] = f
	}
	return lookup
}

// statusWorsened returns true if newStatus is worse than oldStatus.
func statusWorsened(old, newStatus models.Status) bool {
	rank := map[models.Status]int{
		models.StatusPass:  0,
		models.StatusWarn:  1,
		models.StatusFail:  2,
		models.StatusError: 3,
		models.StatusSkip:  -1,
	}
	return rank[newStatus] > rank[old]
}

// statusImproved returns true if newStatus is better than oldStatus.
func statusImproved(old, newStatus models.Status) bool {
	return statusWorsened(newStatus, old)
}

// computeNetChange returns a human-readable description of the net change.
func computeNetChange(baseline, current *models.ReportSummary) string {
	failDelta := current.Fail - baseline.Fail
	errDelta := current.Error - baseline.Error
	warnDelta := current.Warn - baseline.Warn

	if failDelta == 0 && errDelta == 0 && warnDelta == 0 {
		return "no change"
	}

	var parts []string
	if failDelta < 0 {
		parts = append(parts, fmt.Sprintf("%d fewer failures", -failDelta))
	} else if failDelta > 0 {
		parts = append(parts, fmt.Sprintf("%d more failures", failDelta))
	}
	if errDelta < 0 {
		parts = append(parts, fmt.Sprintf("%d fewer errors", -errDelta))
	} else if errDelta > 0 {
		parts = append(parts, fmt.Sprintf("%d more errors", errDelta))
	}
	if warnDelta < 0 {
		parts = append(parts, fmt.Sprintf("%d fewer warnings", -warnDelta))
	} else if warnDelta > 0 {
		parts = append(parts, fmt.Sprintf("%d more warnings", warnDelta))
	}

	return strings.Join(parts, ", ")
}
