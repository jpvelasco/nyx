package audit

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/providers"
)

func TestACLDriftComparison(t *testing.T) {
	policies := []intent.Policy{{Name: "iot-deny", Scope: "gateway"}, {Name: "servers-deny"}, {Name: "trusted-allow", Scope: "switch"}}
	rules := []providers.ObservedACL{{Name: "iot-deny", Scope: "switch"}, {Name: "trusted-allow", Scope: "switch"}}
	for _, tc := range []struct {
		name    string
		missing []string
		want    models.Status
		absent  []string
	}{
		{"complete", nil, models.StatusFail, []string{"gateway/iot-deny", "servers-deny"}},
		{"unread gateway", []string{"gateway"}, models.StatusWarn, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := compareACLs("omada", policies, providers.ACLObservation{Rules: rules, UnknownScopes: tc.missing})
			if got.Status != tc.want || !slices.Equal(got.Observed["declared_but_absent"].([]string), tc.absent) || !slices.Equal(got.Observed["live_but_undeclared"].([]string), []string{"switch/iot-deny"}) {
				t.Fatalf("drift = %#v", got)
			}
		})
	}
}

func TestUncoveredDirection(t *testing.T) {
	spec := &intent.Spec{Networks: []intent.Network{{Name: "iot", Zone: "devices", Gateway: "10.0.60.1"}, {Name: "trusted", Zone: "trusted", Gateway: "10.0.10.1"}}, Policies: []intent.Policy{{Name: "reverse", From: "trusted", To: "devices", Action: "deny"}}, Assertions: []intent.Assertion{{Type: "isolation", From: "iot", To: "trusted"}}}
	result := models.NewCheckResult("system", "isolation", "local", "iot -> trusted")
	if got := uncoveredDirections(spec, []models.CheckResult{*result}); len(got) != 0 {
		t.Fatalf("unknown observations produced %v", got)
	}
	result.Observed["source_network"] = "iot"
	result.Observed["unreachable_gateways"] = []string{"10.0.10.1"}
	if got := uncoveredDirections(spec, []models.CheckResult{*result}); !slices.Equal(got, []string{"iot -> trusted"}) {
		t.Fatalf("uncovered = %v", got)
	}
	spec.Policies = append(spec.Policies, intent.Policy{Name: "covered", From: "devices", To: "trusted", Action: "deny"})
	if got := uncoveredDirections(spec, []models.CheckResult{*result}); len(got) != 0 {
		t.Fatalf("covered = %v", got)
	}
}

type driftTestProvider struct {
	recordingACLProvider
	obs providers.ACLObservation
}

func (*driftTestProvider) Name() string { return "opnsense" }
func (p *driftTestProvider) ObserveACLs(_ context.Context, opts providers.ImportOptions, _ []intent.Network) (providers.ACLObservation, error) {
	if opts.Host != "gateway.example" || opts.ClientID != "fixture" || opts.ClientSecret != "fixture" || !opts.SkipTLSVerify {
		return providers.ACLObservation{}, errors.New("incorrect controller options")
	}
	return p.obs, nil
}
func TestACLDriftEngine(t *testing.T) {
	providers.Reset()
	t.Cleanup(providers.Reset)
	p := &driftTestProvider{obs: providers.ACLObservation{Rules: []providers.ObservedACL{{Name: "live-only", Scope: "filter"}}}}
	if err := providers.Register(p); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPNSENSE_HOST", "gateway.example")
	t.Setenv("OPNSENSE_API_KEY", "fixture")
	t.Setenv("OPNSENSE_API_SECRET", "fixture")
	for _, tc := range []struct {
		name       string
		assertions []intent.Assertion
		wantIndex  int
	}{
		{"explicit", []intent.Assertion{{Type: "acl_drift", Provider: "opnsense"}}, 0},
		{"legacy ACL assertion", []intent.Assertion{{Type: "acl_check", Provider: "opnsense", Policy: "missing", Expect: "enforced"}}, 1},
		{"already explicit", []intent.Assertion{{Type: "acl_check", Provider: "opnsense", Policy: "missing", Expect: "enforced"}, {Type: "acl_drift", Provider: "opnsense"}}, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eng := NewEngine(&intent.Spec{Policies: []intent.Policy{{Name: "missing", Scope: "filter"}, {Name: "other-provider", Scope: "gateway"}}, Assertions: tc.assertions})
			eng.SkipTLSVerify = true
			report, err := eng.Run(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if len(report.Findings) != tc.wantIndex+1 {
				t.Fatalf("unexpected findings: %v", report.Findings)
			}
			r := report.Findings[tc.wantIndex]
			if r.CheckType != "acl_drift" || r.Status != models.StatusFail || !slices.Equal(r.Observed["declared_but_absent"].([]string), []string{"filter/missing"}) {
				t.Fatalf("drift: %v", r)
			}
		})
	}
	t.Setenv("OPNSENSE_API_KEY", "")
	e := NewEngine(&intent.Spec{})
	e.CredentialsPath = filepath.Join(t.TempDir(), "credentials.json")
	r, err := e.runACLDrift(t.Context(), "opnsense")
	if err != nil || r.Status != models.StatusWarn || !strings.Contains(r.Summary, "unknown") {
		t.Fatalf("missing credentials: %v, %v", r, err)
	}
}

func TestACLDrift_NoObservedRuleIsUnknown(t *testing.T) {
	for _, tc := range []struct {
		p    string
		obs  providers.ACLObservation
		want models.Status
	}{
		{"omada", providers.ACLObservation{}, models.StatusPass},
		{"omada", providers.ACLObservation{Rules: []providers.ObservedACL{{Scope: "gateway"}}}, models.StatusWarn},
	} {
		if got := compareACLs(tc.p, nil, tc.obs); got.Status != tc.want {
			t.Errorf("%v: got %s, want %s", tc.obs, got.Status, tc.want)
		}
	}
}

func TestACLDrift_ProviderDiagnosticsAndRuleText(t *testing.T) {
	providers.Reset()
	t.Cleanup(providers.Reset)
	if err := providers.Register(&driftTestProvider{}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPNSENSE_HOST", "gateway.example")
	t.Setenv("OPNSENSE_API_KEY", "fixture")
	t.Setenv("OPNSENSE_API_SECRET", "fixture")
	// With TLS verification enabled this fake returns a diagnostic. The
	// public report should carry the failure category, without its raw text.
	result, err := NewEngine(&intent.Spec{}).runACLDrift(t.Context(), "opnsense")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(result)
	if err != nil || result.Status != models.StatusWarn || strings.Contains(string(data), "incorrect controller options") {
		t.Fatalf("provider error exposed: %v", result)
	}
	r := compareACLs("opnsense", nil, providers.ACLObservation{Rules: []providers.ObservedACL{{Scope: "filter", Name: "two\nlines"}}})
	if len(r.Evidence) != 1 || strings.ContainsRune(r.Evidence[0], '\n') || r.Observed["live_but_undeclared"].([]string)[0] != "filter/two\nlines" {
		t.Fatalf("rule name was not rendered as a single quoted value: %v", r.Evidence)
	}
}
