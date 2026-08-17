package cli

import (
	"testing"

	"github.com/jpvelasco/nyx/internal/models"
)

func TestBuildInitSpec_ScanModePolite(t *testing.T) {
	nets := []initNet{
		{cidr: "10.0.0.0/24", gateway: "10.0.0.1", localIP: "10.0.0.5", hosts: 3, ifaceName: "eth0"},
		{cidr: "10.0.10.0/24", gateway: "10.0.10.1", localIP: "10.0.10.5", hosts: 0, ifaceName: "eth1"},
	}
	spec := buildInitSpec(nets)
	if len(spec.Networks) != 2 {
		t.Fatalf("networks = %d, want 2", len(spec.Networks))
	}
	found := false
	for _, a := range spec.Assertions {
		if a.Type != "subnet_discovery" {
			continue
		}
		found = true
		// Generated specs must default to polite scans: normal/aggressive
		// modes trigger SYN-flood alarms on SDN controllers.
		if a.ScanMode != "polite" {
			t.Errorf("subnet_discovery %q scan_mode = %q, want %q", a.Network, a.ScanMode, "polite")
		}
	}
	if !found {
		t.Errorf("no subnet_discovery assertions in generated spec")
	}
}

func TestHostCountFrom(t *testing.T) {
	tests := []struct {
		name   string
		result *models.CheckResult
		want   int
	}{
		{"nil result", nil, 0},
		{"no observed key", &models.CheckResult{Observed: map[string]interface{}{}}, 0},
		{"int total", &models.CheckResult{Observed: map[string]interface{}{"total": 7}}, 7},
		{"float64 total", &models.CheckResult{Observed: map[string]interface{}{"total": float64(12)}}, 12},
		{"wrong type", &models.CheckResult{Observed: map[string]interface{}{"total": "seven"}}, 0},
		{"hosts_up ignored", &models.CheckResult{Observed: map[string]interface{}{"hosts_up": 5, "total": 3}}, 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := hostCountFrom(tc.result); got != tc.want {
				t.Errorf("hostCountFrom() = %d, want %d", got, tc.want)
			}
		})
	}
}
