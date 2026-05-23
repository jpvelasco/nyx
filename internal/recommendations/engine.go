package recommendations

import (
	"github.com/velasco-jp/nyx/internal/intent"
	"github.com/velasco-jp/nyx/internal/models"
)

// Recommendation represents an actionable fix for one or more failures
type Recommendation struct {
	Priority    int      `json:"priority"`
	Category    string   `json:"category"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Remediation string   `json:"remediation"`
	Affected    []string `json:"affected"`
	SpecPatch   string   `json:"spec_patch,omitempty"`
}

// GenerateRecommendations analyzes failures and produces prioritized recommendations
func GenerateRecommendations(failures []models.CheckResult, networks map[string]*intent.Network) ([]Recommendation, error) {
	// For now, return empty recommendations list. Future sprints will expand this.
	return []Recommendation{}, nil
}
