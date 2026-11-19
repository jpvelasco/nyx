package audit

import (
	"context"
	"fmt"
	"time"

	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/providers"
)

// wlanScheduleMargin is how long after the expected fire a run still counts
// as current: controller scheduler lateness plus the time a multi-AP
// optimization takes to complete and record its history row.
const wlanScheduleMargin = 20 * time.Minute

func (e *Engine) runWLANScheduleLiveness(ctx context.Context, provider string) (*models.CheckResult, error) {
	observer, ok := providers.Get(provider).(providers.WLANScheduleObserver)
	opts := e.controllerOptions(provider)
	var observation providers.WLANScheduleObservation
	var unavailable string
	switch {
	case !ok:
		unavailable = "provider does not support WLAN schedule observation"
	case opts.Host == "" || opts.ClientID == "" || opts.ClientSecret == "":
		unavailable = "provider credentials are missing"
	default:
		var err error
		observation, err = observer.ObserveWLANSchedule(ctx, opts)
		if err != nil {
			unavailable = "could not read WLAN optimization schedule"
		}
	}
	if unavailable != "" {
		r := models.NewCheckResult(provider, "wlan_schedule_liveness", provider, provider)
		r.Status = models.StatusWarn
		r.Summary = "WLAN optimization schedule unknown: " + unavailable
		r.Finish()
		return r, nil
	}
	return compareWLANSchedule(provider, observation), nil
}

// compareWLANSchedule judges the newest history row against the scheduled
// occurrence in the controller's own wall clock, so local/controller clock
// drift cancels out.
func compareWLANSchedule(provider string, obs providers.WLANScheduleObservation) *models.CheckResult {
	result := models.NewCheckResult(provider, "wlan_schedule_liveness", provider, provider)
	result.Observed["schedule_enabled"] = obs.ScheduleEnabled
	result.Observed["timing_type"] = obs.TimingType
	result.Observed["occurrence"] = fmt.Sprintf("%02d:%02d", obs.OccurrenceHour, obs.OccurrenceMinute)
	now := obs.ControllerNow
	if !now.IsZero() {
		result.Observed["controller_now"] = now.UTC().Format(time.RFC3339)
	}
	lastRunText := "never"
	if !obs.LastRunTime.IsZero() {
		lastRunText = fmt.Sprintf("%s (%d APs)", obs.LastRunTime.UTC().Format(time.RFC3339), obs.LastRunAPCount)
		result.Observed["last_run"] = obs.LastRunTime.UTC().Format(time.RFC3339)
		result.Observed["last_run_ap_count"] = obs.LastRunAPCount
		result.Observed["last_run_msg_type"] = obs.LastRunMessageType
		if obs.LastRunReason != "" {
			result.Observed["last_run_reason"] = obs.LastRunReason
		}
	}

	switch {
	case !obs.ScheduleEnabled:
		result.Status = models.StatusPass
		result.Summary = "WLAN optimization schedule is disabled"
	case obs.TimingType != 1:
		result.Status = models.StatusWarn
		result.Summary = fmt.Sprintf("unsupported WLAN optimization timing type %d (daily = 1); the schedule cannot be evaluated", obs.TimingType)
	case now.IsZero():
		result.Status = models.StatusWarn
		result.Summary = "controller clock unknown; the WLAN optimization schedule cannot be evaluated"
	default:
		expected := time.Date(now.Year(), now.Month(), now.Day(), obs.OccurrenceHour, obs.OccurrenceMinute, 0, 0, now.Location())
		if expected.After(now) {
			expected = expected.AddDate(0, 0, -1)
		}
		result.Observed["expected_fire"] = expected.UTC().Format(time.RFC3339)
		ranAtOrAfter := !obs.LastRunTime.IsZero() && !obs.LastRunTime.Before(expected)
		switch {
		case ranAtOrAfter && obs.LastRunAPCount > 0:
			result.Status = models.StatusPass
			result.Summary = fmt.Sprintf("WLAN optimization optimized %d APs at %s, at or after the expected fire %s",
				obs.LastRunAPCount, obs.LastRunTime.UTC().Format(time.RFC3339), expected.UTC().Format(time.RFC3339))
		case !ranAtOrAfter && now.Sub(expected) <= wlanScheduleMargin:
			result.Status = models.StatusPass
			result.Summary = fmt.Sprintf("WLAN optimization schedule is current (expected fire %s, now %s)",
				expected.UTC().Format(time.RFC3339), now.UTC().Format(time.RFC3339))
		case ranAtOrAfter:
			// The scheduler fired but the run optimized zero APs: a skip,
			// surfaced with the controller's own reason when it gave one.
			result.Status = models.StatusWarn
			result.Summary = fmt.Sprintf("WLAN optimization fired at %s but optimized no APs (expected fire %s)",
				obs.LastRunTime.UTC().Format(time.RFC3339), expected.UTC().Format(time.RFC3339))
			result.Violations = append(result.Violations,
				"fired at: "+obs.LastRunTime.UTC().Format(time.RFC3339)+" (apNum=0)",
			)
			if obs.LastRunReason != "" {
				result.Violations = append(result.Violations, "controller reason: "+obs.LastRunReason)
			}
			result.Violations = append(result.Violations,
				"candidate causes: APs offline or unmanaged at fire time, an in-progress channel deployment holding the RF optimization lock, or a controller-side scheduling defect (manual runs succeed where scheduled runs skip)",
				"check the controller system log for RFPlanningOptimizationHandler lines (on the OC200 the log is only reachable through the web UI; nyx issue #322 tracks controller-side forwarding)",
			)
		default:
			result.Status = models.StatusWarn
			result.Summary = fmt.Sprintf("WLAN optimization did not run at the expected fire %s (last run: %s)",
				expected.UTC().Format(time.RFC3339), lastRunText)
			result.Violations = append(result.Violations,
				"expected fire: "+expected.UTC().Format(time.RFC3339),
				"last run: "+lastRunText,
				"candidate causes: no online APs at fire time, an in-progress channel deployment holding the RF optimization lock, or schedule configuration lost after a controller reboot",
				"check the controller system log for RFPlanningOptimizationHandler lines (on the OC200 the log is only reachable through the web UI; nyx issue #322 tracks controller-side forwarding)",
			)
		}
	}

	result.Finish()
	return result
}
