package mcp_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/mcp"
	"github.com/jpvelasco/nyx/internal/models"

	// Blank imports to trigger provider registration (for provider_list tool tests)
	_ "github.com/jpvelasco/nyx/internal/providers/omada"
	_ "github.com/jpvelasco/nyx/internal/providers/opnsense"
)

func TestVerifyIsolationToolReturnsCheckResult(t *testing.T) {
	s := mcp.NewServer()
	ctx := context.Background()

	resultText, isError := s.DispatchToolForTest(ctx, "verify_isolation", map[string]interface{}{
		"from": "clients",
		"to":   "127.0.0.1",
	})

	if isError && strings.Contains(resultText, "not yet implemented") {
		t.Error("verify_isolation returned stub error")
	}

	var result models.CheckResult
	if err := json.Unmarshal([]byte(resultText), &result); err != nil {
		t.Errorf("verify_isolation did not return valid CheckResult JSON: %v\nOutput: %s", err, resultText)
	}
	if result.Status == "" {
		t.Error("CheckResult.Status is empty")
	}
}

func TestLoadSpecTool(t *testing.T) {
	s := mcp.NewServer()
	ctx := context.Background()

	// valid spec via testdata (relative from module root when test runs)
	resultText, isError := s.DispatchToolForTest(ctx, "load_spec", map[string]interface{}{
		"spec_file": "../../testdata/valid_spec.yaml",
	})
	if isError {
		t.Fatalf("load_spec on valid should not error: %s", resultText)
	}
	if !strings.Contains(resultText, "site") {
		t.Error("expected spec content in output")
	}
}

func TestLoadSpecToolInvalid(t *testing.T) {
	s := mcp.NewServer()
	ctx := context.Background()

	_, isError := s.DispatchToolForTest(ctx, "load_spec", map[string]interface{}{
		"spec_file": "../../testdata/invalid_spec.yaml",
	})
	if !isError {
		t.Error("expected error for invalid spec")
	}
}

func TestProviderListTool(t *testing.T) {
	s := mcp.NewServer()
	ctx := context.Background()

	resultText, isError := s.DispatchToolForTest(ctx, "provider_list", map[string]interface{}{})
	if isError {
		t.Fatalf("provider_list error: %s", resultText)
	}
	// should contain at least omada and opnsense (registered via blank imports)
	if !strings.Contains(resultText, "omada") || !strings.Contains(resultText, "opnsense") {
		t.Errorf("expected providers in list, got: %s", resultText)
	}
}

func TestRunDoctorTool(t *testing.T) {
	s := mcp.NewServer()
	ctx := context.Background()

	resultText, isError := s.DispatchToolForTest(ctx, "run_doctor", map[string]interface{}{})
	if isError {
		t.Fatalf("run_doctor error: %s", resultText)
	}
	if !strings.Contains(resultText, "nmap") {
		t.Error("doctor output should mention nmap check")
	}
}

func TestDiscoverSubnetMissingArg(t *testing.T) {
	s := mcp.NewServer()
	ctx := context.Background()

	_, isError := s.DispatchToolForTest(ctx, "discover_subnet", map[string]interface{}{})
	if !isError {
		t.Error("expected error when subnet arg missing")
	}
}
