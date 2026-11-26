package service

import (
	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/snapshot"
	"github.com/jpvelasco/nyx/internal/testutil/providerfixture"
	"path/filepath"
	"testing"
	"time"
)

func TestMapDriftSavedScopeAndPolicies(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("NYX_CREDENTIALS_FILE", filepath.Join(home, "credentials.json"))
	providerfixture.IsolateProviders(t)
	if err := providers.Register(&providerfixture.ReadOnlyAdapter{}); err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	s := NewTopologyService()
	opts := NetworkMapOptions{Connections: []string{"synthetic/default"}}
	if err := snapshot.SetBaseline("fixture", &models.AuditReport{Findings: []models.CheckResult{{CheckType: "service_policy", Target: "management service", Status: models.StatusPass, Expected: map[string]interface{}{"policy": "management", "outcome": "deny"}}}}); err != nil {
		t.Fatal(err)
	}
	capture := func(name string) {
		t.Helper()
		if _, err := s.CaptureMap(ctx, opts, name, "baseline.json", false); err != nil {
			t.Fatal(err)
		}
	}
	capture("first")
	capture("second")
	if _, err := s.CaptureMap(ctx, opts, "first", "", false); err == nil {
		t.Fatal("overwrote snapshot")
	}
	if _, err := s.CaptureMap(ctx, opts, "bad", "../outside", false); err == nil {
		t.Fatal("invalid audit basename accepted")
	}
	for _, p := range []struct {
		a, b, audit, age string
		opts             NetworkMapOptions
		ok               bool
	}{{"first", "second", "", "", NetworkMapOptions{}, true}, {"first", "", "baseline.json", "1h", NetworkMapOptions{}, true}, {"first", "second", "", "bad", NetworkMapOptions{}, false}, {"missing", "second", "", "", NetworkMapOptions{}, false}, {"first", "missing", "", "", NetworkMapOptions{}, false}, {"first", "second", "baseline.json", "", NetworkMapOptions{}, false}, {"first", "", "", "", NetworkMapOptions{Connections: []string{"missing"}}, false}} {
		r, err := s.MapDrift(ctx, p.opts, p.a, p.b, p.audit, p.age)
		if (err == nil) != p.ok {
			t.Fatalf("before %s after %s: %v", p.a, p.b, err)
		}
		if p.ok && r.Before.After(r.After) {
			t.Fatal("reversed interval")
		}
	}
	c, err := snapshot.LoadNetworkMapCapture("second")
	if err != nil || len(c.Policies) != 1 {
		t.Fatal(c, err)
	}
	c.At = c.At.Add(-time.Hour)
	if err := snapshot.SaveNetworkMapCapture("second", c, true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.MapDrift(ctx, NetworkMapOptions{}, "first", "second", "", ""); err == nil {
		t.Fatal("accepted reversed capture order")
	}
}
