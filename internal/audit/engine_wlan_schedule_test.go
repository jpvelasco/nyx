package audit

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/providers"
)

// schedTestProvider is a fake omada provider with a fixed WLAN schedule
// observation, for engine-level wlan_schedule_liveness tests.
type schedTestProvider struct {
	recordingACLProvider
	obs  providers.WLANScheduleObservation
	fail error
}

func (*schedTestProvider) Name() string { return "omada" }

func (p *schedTestProvider) ObserveWLANSchedule(_ context.Context, opts providers.ImportOptions) (providers.WLANScheduleObservation, error) {
	if opts.Host != "controller.example" || opts.ClientID != "fixture" || opts.ClientSecret != "fixture" {
		return providers.WLANScheduleObservation{}, errors.New("incorrect controller options")
	}
	return p.obs, p.fail
}

func TestCompareWLANSchedule(t *testing.T) {
	day := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	base := func() providers.WLANScheduleObservation {
		return providers.WLANScheduleObservation{
			ScheduleEnabled:  true,
			TimingType:       1,
			OccurrenceHour:   10,
			OccurrenceMinute: 0,
			ControllerNow:    day.Add(30 * time.Minute),
		}
	}
	for _, tc := range []struct {
		name   string
		obs    providers.WLANScheduleObservation
		want   models.Status
		substr []string
		viol   []string
	}{
		{
			name:   "disabled schedule passes",
			obs:    func() providers.WLANScheduleObservation { o := base(); o.ScheduleEnabled = false; return o }(),
			want:   models.StatusPass,
			substr: []string{"disabled"},
		},
		{
			name:   "unsupported timing type warns",
			obs:    func() providers.WLANScheduleObservation { o := base(); o.TimingType = 2; return o }(),
			want:   models.StatusWarn,
			substr: []string{"unsupported"},
		},
		{
			name:   "unknown controller clock warns",
			obs:    func() providers.WLANScheduleObservation { o := base(); o.ControllerNow = time.Time{}; return o }(),
			want:   models.StatusWarn,
			substr: []string{"clock unknown"},
		},
		{
			name: "within margin without history passes",
			obs: func() providers.WLANScheduleObservation {
				o := base()
				o.ControllerNow = day.Add(10*time.Hour + 5*time.Minute)
				return o
			}(),
			want:   models.StatusPass,
			substr: []string{"current"},
		},
		{
			name: "run at or after expected fire passes",
			obs: func() providers.WLANScheduleObservation {
				o := base()
				o.LastRunTime = day.Add(10*time.Hour + 1*time.Minute)
				o.LastRunAPCount = 7
				return o
			}(),
			want:   models.StatusPass,
			substr: []string{"optimized 7 APs"},
		},
		{
			name: "fire with zero APs warns with controller reason",
			obs: func() providers.WLANScheduleObservation {
				o := base()
				o.LastRunTime = day.Add(10 * time.Hour)
				o.LastRunMessageType = 7
				o.LastRunReason = "No APs available for WLAN Optimization."
				return o
			}(),
			want:   models.StatusWarn,
			substr: []string{"optimized no APs"},
			viol:   []string{"apNum=0", "controller reason: No APs available for WLAN Optimization."},
		},
		{
			name: "zero AP skip inside margin still warns",
			obs: func() providers.WLANScheduleObservation {
				o := base()
				o.ControllerNow = day.Add(10*time.Hour + 5*time.Minute)
				o.LastRunTime = day.Add(10 * time.Hour)
				return o
			}(),
			want:   models.StatusWarn,
			substr: []string{"optimized no APs"},
		},
		{
			name: "stale last run warns",
			obs: func() providers.WLANScheduleObservation {
				o := base()
				o.ControllerNow = day.Add(12 * time.Hour)
				o.LastRunTime = day.Add(-14 * time.Hour) // yesterday 10:00
				return o
			}(),
			want:   models.StatusWarn,
			substr: []string{"did not run"},
		},
		{
			name: "expected fire in the future compares to yesterday",
			obs: func() providers.WLANScheduleObservation {
				o := base()
				o.ControllerNow = day.Add(8 * time.Hour) // 08:00 today
				o.LastRunTime = day.Add(-2 * time.Hour)  // yesterday 22:00
				o.LastRunAPCount = 1
				return o
			}(),
			want:   models.StatusPass,
			substr: []string{"optimized 1 APs"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := compareWLANSchedule("omada", tc.obs)
			if got.Status != tc.want {
				t.Fatalf("status = %s (%s), want %s", got.Status, got.Summary, tc.want)
			}
			for _, s := range tc.substr {
				if !strings.Contains(got.Summary, s) {
					t.Errorf("summary %q missing %q", got.Summary, s)
				}
			}
			for _, s := range tc.viol {
				found := false
				for _, v := range got.Violations {
					if strings.Contains(v, s) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("violations %v missing %q", got.Violations, s)
				}
			}
		})
	}
}

func TestCompareWLANScheduleObserved(t *testing.T) {
	day := time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)
	obs := providers.WLANScheduleObservation{
		ScheduleEnabled:    true,
		TimingType:         1,
		OccurrenceHour:     10,
		OccurrenceMinute:   0,
		ControllerNow:      day.Add(10*time.Hour + 30*time.Minute),
		LastRunTime:        day.Add(10 * time.Hour),
		LastRunMessageType: 7,
		LastRunReason:      "No APs available for WLAN Optimization.",
	}
	got := compareWLANSchedule("omada", obs)
	if got.Observed["expected_fire"] != "2026-11-19T10:00:00Z" || got.Observed["last_run"] != "2026-11-19T10:00:00Z" {
		t.Fatalf("observed = %v", got.Observed)
	}
	if got.Observed["last_run_msg_type"] != 7 || got.Observed["last_run_reason"] != "No APs available for WLAN Optimization." {
		t.Fatalf("observed = %v", got.Observed)
	}
}

func TestWLANScheduleLivenessEngine(t *testing.T) {
	providers.Reset()
	t.Cleanup(providers.Reset)
	p := &schedTestProvider{obs: providers.WLANScheduleObservation{
		ScheduleEnabled:    true,
		TimingType:         1,
		OccurrenceHour:     10,
		OccurrenceMinute:   0,
		ControllerNow:      time.Date(2026, 11, 19, 10, 5, 0, 0, time.UTC),
		LastRunTime:        time.Date(2026, 11, 19, 10, 0, 1, 0, time.UTC),
		LastRunAPCount:     7,
		LastRunMessageType: -1,
	}}
	if err := providers.Register(p); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OMADA_HOST", "controller.example")
	t.Setenv("OMADA_CLIENT_ID", "fixture")
	t.Setenv("OMADA_CLIENT_SECRET", "fixture")
	eng := NewEngine(&intent.Spec{Version: 1, Site: "test", Assertions: []intent.Assertion{{Type: "wlan_schedule_liveness", Provider: "omada"}}})
	report, err := eng.Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %v", report.Findings)
	}
	r := report.Findings[0]
	if r.CheckType != "wlan_schedule_liveness" || r.Status != models.StatusPass || !strings.Contains(r.Summary, "optimized 7 APs") {
		t.Fatalf("liveness = %v", r)
	}
}

func TestWLANScheduleLivenessUnavailable(t *testing.T) {
	providers.Reset()
	t.Cleanup(providers.Reset)

	e := NewEngine(&intent.Spec{})
	r, err := e.runWLANScheduleLiveness(t.Context(), "nonexistent")
	if err != nil || r.Status != models.StatusWarn || !strings.Contains(r.Summary, "does not support") {
		t.Fatalf("unsupported provider: %v, %v", r, err)
	}

	p := &schedTestProvider{}
	if err := providers.Register(p); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OMADA_HOST", "")
	t.Setenv("OMADA_CLIENT_ID", "")
	t.Setenv("OMADA_CLIENT_SECRET", "")
	t.Setenv("OMADA_SITE", "")
	e = NewEngine(&intent.Spec{})
	e.CredentialsPath = filepath.Join(t.TempDir(), "credentials.json")
	r, err = e.runWLANScheduleLiveness(t.Context(), "omada")
	if err != nil || r.Status != models.StatusWarn || !strings.Contains(r.Summary, "credentials are missing") {
		t.Fatalf("missing credentials: %v, %v", r, err)
	}

	t.Setenv("OMADA_HOST", "controller.example")
	t.Setenv("OMADA_CLIENT_ID", "fixture")
	t.Setenv("OMADA_CLIENT_SECRET", "fixture")
	p.fail = errors.New("boom")
	r, err = e.runWLANScheduleLiveness(t.Context(), "omada")
	if err != nil || r.Status != models.StatusWarn || !strings.Contains(r.Summary, "could not read") {
		t.Fatalf("observe error: %v, %v", r, err)
	}
}
