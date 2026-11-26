package cli

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/mcp"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/jpvelasco/nyx/internal/topology"
)

func TestClientLocationTransportParity(t *testing.T) {
	configureMapFixtures(t)
	old := outputPath
	t.Cleanup(func() { outputPath = old })
	fixtureDir := t.TempDir()
	outputPath = filepath.Join(fixtureDir, "location.json")
	const selector = "02:aa:bb:cc:dd:04"
	cmd := newClientLocationCmd()
	cmd.SetContext(t.Context())
	cmd.SetArgs([]string{selector, "--skip-tls-verify"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	raw, err := fs.ReadFile(os.DirFS(fixtureDir), "location.json")
	if err != nil {
		t.Fatal(err)
	}
	var report topology.ClientLocation
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "located" || report.DownstreamPort != "unknown" || len(report.Evidence) != 3 {
		t.Fatalf("fixture evidence %+v", report)
	}
	text, failed := mcp.NewServerWithLogger(nil).DispatchToolForTest(t.Context(), service.ClientLocationTool, map[string]any{"mac": selector, "skip_tls_verify": true})
	var wrapped struct {
		Data      topology.ClientLocation `json:"data"`
		Untrusted bool                    `json:"untrusted_data"`
	}
	if failed || json.Unmarshal([]byte(text), &wrapped) != nil || !wrapped.Untrusted || !reflect.DeepEqual(report, wrapped.Data) || strings.Contains(text, selector) {
		t.Fatal("CLI/MCP attachment evidence or privacy differs")
	}
}
