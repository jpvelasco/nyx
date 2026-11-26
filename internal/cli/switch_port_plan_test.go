package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/mcp"
	"github.com/jpvelasco/nyx/internal/service"
)

func TestSwitchPortPlanParity(t *testing.T) {
	configureMapFixtures(t)
	old := outputPath
	t.Cleanup(func() { outputPath = old })
	outputPath = filepath.Join(t.TempDir(), "plan.json")
	const mac = "02:aa:bb:cc:dd:02"
	const policy = `{"management_vlan":11,"ports":[{"port":8,"role":"ap-uplink","native":"management","tagged":["gaming"]},{"port":9,"role":"access","native":"gaming","client_mac":"02:aa:bb:cc:dd:05"},{"port":1,"role":"access","native":"gaming"}]}`
	cmd := newSwitchPortsCmd()
	cmd.SetContext(t.Context())
	cmd.SetArgs([]string{"omada/home", mac, policy, "--skip-tls-verify"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), mac) || strings.Contains(string(b), "02:aa:bb:cc:dd:05") {
		t.Fatal("private identifiers in default port plan")
	}
	var plan service.SwitchPortPlan
	if err := json.Unmarshal(b, &plan); err != nil {
		t.Fatal(err)
	}
	if len(plan.Ports) != 3 || !plan.Ports[0].Eligible || !plan.Ports[1].Eligible || plan.Ports[2].Eligible || plan.Ports[2].Desired != nil || plan.Ports[1].Revision == "" {
		t.Fatalf("unexpected preview %+v", plan)
	}
	text, failed := mcp.NewServerWithLogger(nil).DispatchToolForTest(t.Context(), service.SwitchPortsTool, map[string]any{"connection": "omada/home", "switch_mac": mac, "policy": policy, "skip_tls_verify": true})
	var env struct {
		Data service.SwitchPortPlan `json:"data"`
	}
	if failed || json.Unmarshal([]byte(text), &env) != nil || !reflect.DeepEqual(plan, env.Data) {
		t.Fatalf("CLI/MCP plans differ")
	}
}
