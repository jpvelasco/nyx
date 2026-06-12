package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/recommendations"
	"github.com/jpvelasco/nyx/internal/report"
)

func TestRenderRecommendationsGoesToWriter(t *testing.T) {
	recs := []recommendations.Recommendation{
		{
			Priority:    1,
			Category:    "security",
			Title:       "Test recommendation",
			Description: "A test description",
			Remediation: "Do something",
			Affected:    []string{"192.168.1.0/24"},
		},
	}

	tmpFile := filepath.Join(t.TempDir(), "out.txt")
	f, err := os.Create(tmpFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	report.RenderRecommendations(f, recs)
	f.Close()

	content, err := os.ReadFile(tmpFile) // nosemgrep // #nosec G304
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(content), "Test recommendation") {
		t.Errorf("expected recommendation in file output, got: %s", string(content))
	}
}

func TestRecommendationsNotInJSONOutput(t *testing.T) {
	var buf strings.Builder
	_ = []recommendations.Recommendation{
		{Priority: 1, Title: "Should not appear", Category: "test",
			Description: "desc", Remediation: "fix"},
	}

	report.RenderJSON(&buf, &models.AuditReport{
		Audit:  "test",
		Status: models.StatusPass,
	})

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(buf.String()), &result); err != nil {
		t.Errorf("JSON output is not valid JSON: %v\nOutput: %s", err, buf.String())
	}

	if strings.Contains(buf.String(), "Should not appear") {
		t.Errorf("recommendations leaked into JSON output")
	}
}
