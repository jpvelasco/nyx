package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/mcp"
	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/probe/fake"
	"gopkg.in/yaml.v3"
)

func TestServicePolicyCLIAndMCP(t *testing.T) {
	saveRestoreGlobals(t)
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("USERPROFILE", tmp)
	saved := lastAuditReport
	t.Cleanup(func() { lastAuditReport = saved })
	key := filepath.Join(tmp, "probe-key")
	fake.WriteKey(t, key)
	declare := func(name string, code uint32) intent.Probe {
		srv := fake.Start(t, fake.Options{ExecReply: true, OnExec: func(string) (string, uint32) { return "", code }})
		return intent.Probe{Name: name, Host: "127.0.0.1", Port: srv.Port, Key: key, User: "fixture", VLAN: name, SkipHostKeyVerify: true}
	}
	spec := intent.Spec{Version: 1, Site: "trusted",
		Networks: []intent.Network{{Name: "iot", CIDR: "10.0.60.0/24"}, {Name: "management", CIDR: "10.0.11.0/24"}},
		Probes:   []intent.Probe{declare("iot", 1), declare("management", 0)},
		Policies: []intent.Policy{{Name: "management-access", From: "iot", To: "management", Action: "deny"}},
		Assertions: []intent.Assertion{
			{Name: "source", Type: "port_check", Runner: "iot", Target: "10.0.11.1", Ports: []int{443}, Expect: "closed"},
			{Name: "control", Type: "port_check", Runner: "management", Target: "10.0.11.1", Ports: []int{443}, Expect: "open"},
		},
		ServicePolicies: []intent.ServicePolicy{{Policy: "management-access", Measurement: "source", PositiveControl: "control"}},
	}
	input, err := yaml.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	specFile = filepath.Join(tmp, "intent.yaml")
	if err := os.WriteFile(specFile, input, 0600); err != nil {
		t.Fatal(err)
	}
	outputPath = ""
	jsonOutput = true
	var auditErr error
	cliJSON := captureStdout(func() { auditErr = auditCmd.RunE(auditCmd, nil) })
	var exit *ExitError
	if auditErr != nil && !errors.As(auditErr, &exit) {
		t.Fatal(auditErr)
	}
	mcpJSON, failed := mcp.NewServer().DispatchToolForTest(t.Context(), "run_audit", map[string]any{"spec_file": specFile})
	if failed {
		t.Fatal(mcpJSON)
	}
	finding := func(data []byte) models.CheckResult {
		t.Helper()
		var report models.AuditReport
		if err := json.Unmarshal(data, &report); err != nil {
			t.Fatal(err)
		}
		for _, r := range report.Findings {
			if r.CheckType == "service_policy" {
				return r
			}
		}
		t.Fatal("missing service policy result")
		return models.CheckResult{}
	}
	left, right := finding([]byte(cliJSON)), finding([]byte(mcpJSON))
	if left.Status != models.StatusPass || right.Status != left.Status || !reflect.DeepEqual(left.Observed, right.Observed) || !reflect.DeepEqual(left.Expected, right.Expected) {
		t.Fatal("CLI and MCP returned differing service policy results")
	}
}
