package cli

import (
	"encoding/json"
	"github.com/jpvelasco/nyx/internal/mcp"
	"github.com/jpvelasco/nyx/internal/service"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPathPerformanceTransports(t *testing.T) {
	configureMapFixtures(t)
	old := outputPath
	t.Cleanup(func() { outputPath = old })
	fixtureDir := t.TempDir()
	outputPath = filepath.Join(fixtureDir, "result.json")
	const path = `[{"connection":"omada/home","kind":"switch_port","switch_mac":"02:aa:bb:cc:dd:02","port":8},{"connection":"omada/home","kind":"channel","band":"5g","channel":36,"ap_mac":"02:aa:bb:cc:dd:03"},{"connection":"opnsense/home","kind":"interface","name":"opt1"},{"connection":"opnsense/home","kind":"gateway","name":"gateway"},{"connection":"opnsense/home","kind":"shaper_queue","name":"1.1"}]`
	cmd := newPerformanceCmd()
	cmd.SetContext(t.Context())
	cmd.SetArgs([]string{path, "--interval", "1s", "--skip-tls-verify"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	data, err := fs.ReadFile(os.DirFS(fixtureDir), "result.json")
	if err != nil {
		t.Fatal(err)
	}
	var cli service.PerformanceReport
	if err := json.Unmarshal(data, &cli); err != nil {
		t.Fatal(err)
	}
	text, failed := mcp.NewServerWithLogger(nil).DispatchToolForTest(t.Context(), service.PerformanceTool, map[string]any{"path": path, "interval": "1s", "skip_tls_verify": true})
	var env struct {
		Data service.PerformanceReport `json:"data"`
	}
	if failed || json.Unmarshal([]byte(text), &env) != nil {
		t.Fatal("MCP sampling failed")
	}
	for _, r := range []service.PerformanceReport{cli, env.Data} {
		if len(r.Hops) != 5 || r.Hops[0].After.ObservedMbps == nil || *r.Hops[0].After.ObservedMbps != 1000 || r.Hops[1].After.Interference == nil || *r.Hops[1].After.Interference != 30 || r.Hops[1].Recommendation == "" || r.Hops[2].Status != "idle" || r.Hops[3].After.LatencyMS == nil || r.Hops[4].After.Drops == nil {
			t.Fatalf("incorrect telemetry: %+v", r.Hops)
		}
	}
	if strings.Contains(text, "02:aa:") || strings.Contains(text, "192.0.2.") {
		t.Fatal("private path selectors in response")
	}
}
