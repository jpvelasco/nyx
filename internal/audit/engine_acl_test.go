package audit

import (
	"context"
	"testing"

	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
)

// --- runACLCheck ---

func TestRunACLCheck_PolicyNotFound(t *testing.T) {
	spec := &intent.Spec{Version: 1, Site: "test"}
	a := intent.Assertion{Type: "acl_check", Provider: "omada", Policy: "missing-policy", Expect: "enforced"}
	eng := NewEngine(spec)
	result, err := eng.runACLCheck(context.Background(), a)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != models.StatusError {
		t.Errorf("expected error for missing policy, got %s", result.Status)
	}
}
