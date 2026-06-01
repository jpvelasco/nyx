package mcp_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/mcp"
	"github.com/jpvelasco/nyx/internal/models"
)

func TestVerifyIsolationNotStub(t *testing.T) {
	s := mcp.NewServer()
	ctx := context.Background()

	resultText, isError := s.DispatchToolForTest(ctx, "verify_isolation", map[string]interface{}{
		"from": "clients",
		"to":   "127.0.0.1",
	})

	if isError && strings.Contains(resultText, "not yet implemented") {
		t.Error("verify_isolation is still a stub")
	}

	var result models.CheckResult
	if err := json.Unmarshal([]byte(resultText), &result); err != nil {
		t.Errorf("verify_isolation did not return valid CheckResult JSON: %v\nOutput: %s", err, resultText)
	}
	if result.Status == "" {
		t.Error("CheckResult.Status is empty")
	}
}
