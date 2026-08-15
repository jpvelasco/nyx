package cli

import (
	"testing"

	"github.com/jpvelasco/nyx/internal/models"
)

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
