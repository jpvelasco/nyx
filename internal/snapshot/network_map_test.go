package snapshot

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/topology"
)

func driftFixture(at time.Time, revision bool) NetworkMapCapture {
	m := topology.NetworkMap{Sources: []topology.MapSource{{ID: "c1", Provider: "fixture", Profile: "home", ControllerSite: "lab.example", ObservedAt: &at}}, Resources: []topology.MapResource{{ID: "port", Source: "c1", Kind: "port", NativeID: "switch/8", Port: 8}, {ID: "ssid", Source: "c1", Kind: "ssid", NativeID: "gaming-wifi"}, {ID: "g", Source: "c1", Kind: "segment", NativeID: "gaming", GatewayPrefix: "192.0.2.1/24"}, {ID: "m", Source: "c1", Kind: "segment", NativeID: "management"}}}
	target := "g"
	outcome := "allow"
	if revision {
		target = "m"
		outcome = "deny"
		m.Resources[2].GatewayPrefix = "192.0.2.2/24"
	} else {
		m.Links = append(m.Links, topology.MapLink{From: "port", Relation: "tagged", Targets: []string{"g"}, State: "observed", Evidence: "bound port profile"})
	}
	m.Links = append(m.Links, topology.MapLink{From: "ssid", Relation: "segment", Targets: []string{target}, State: "observed", Evidence: "SSID VLAN"})
	c := NetworkMapCapture{Version: 1, At: at, Map: m}
	c.AddServicePolicies(&Snapshot{RunAt: at, Findings: []models.CheckResult{{CheckType: "service_policy", Target: "management access", Expected: map[string]interface{}{"policy": "management", "outcome": outcome}, Observed: map[string]interface{}{"firewall_evidence": "recorded"}, Status: models.StatusPass}}})
	return c
}
func TestMapDriftEvidence(t *testing.T) {
	now := time.Now().UTC()
	a, b := driftFixture(now, false), driftFixture(now.Add(time.Minute), true)
	r := CompareNetworkMaps(a, b, time.Hour)
	if len(r.Changes) != 4 {
		t.Fatalf("changes: %+v", r.Changes)
	}
	seen := map[string]int{}
	for _, c := range r.Changes {
		seen[c.Change]++
		if c.Reference == "" || c.Evidence == "" || c.Subject == "" {
			t.Fatal(c)
		}
	}
	if seen["address_churn"] != 1 || seen["changed"] != 2 || seen["removed"] != 1 {
		t.Fatal(seen)
	}
	data, _ := json.Marshal(r)
	for _, p := range []string{"192.0.2.", "lab.example", "gaming-wifi", "management access", "switch/8"} {
		if strings.Contains(string(data), p) {
			t.Fatal("private value in drift report")
		}
	}
	// Source-local display and resource ordering are unstable across maps.
	reordered := driftFixture(now, false)
	slices.Reverse(reordered.Map.Resources)
	if r := CompareNetworkMaps(a, reordered, time.Hour); len(r.Changes) != 0 {
		t.Fatalf("order-only drift: %+v", r)
	}
	for _, tc := range []struct {
		name, want string
		edit       func(*NetworkMapCapture)
	}{{"collector down", "unavailable", func(c *NetworkMapCapture) {
		c.Map.Sources[0].Gaps = []string{"unreachable"}
		c.Map.Resources = nil
		c.Map.Links = nil
	}}, {"stale source", "stale", func(c *NetworkMapCapture) { old := now.Add(-time.Hour * 2); c.Map.Sources[0].ObservedAt = &old }}, {"profile unavailable", "unverified", func(c *NetworkMapCapture) {
		c.Map.Sources[0].Gaps = []string{"LAN profiles"}
		c.Map.Links = c.Map.Links[1:]
	}}} {
		t.Run(tc.name, func(t *testing.T) {
			c := driftFixture(now, false)
			tc.edit(&c)
			r := CompareNetworkMaps(a, c, time.Hour)
			var found bool
			for _, row := range r.Changes {
				if row.Change == "removed" || row.Change == "changed" {
					t.Fatalf("invented configuration change %+v", row)
				}
				found = found || row.Change == tc.want
			}
			if !found {
				t.Fatal(r)
			}
		})
	}
}
func TestMapCaptureStore(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	c := driftFixture(time.Now().UTC(), false)
	if err := SaveNetworkMapCapture("before", c, false); err != nil {
		t.Fatal(err)
	}
	if err := SaveNetworkMapCapture("before", c, false); err == nil {
		t.Fatal("overwrote baseline")
	}
	if _, err := LoadNetworkMapCapture("../outside"); err == nil {
		t.Fatal("path escape")
	}
	if _, err := ReadNamedAudit("../outside"); err == nil {
		t.Fatal("invalid audit name")
	}
	loaded, err := LoadNetworkMapCapture("before")
	if err != nil || !loaded.At.Equal(c.At) {
		t.Fatal("saved map missing", err)
	}
	if err := SaveNetworkMapCapture("before", c, true); err != nil {
		t.Fatal(err)
	}
}
