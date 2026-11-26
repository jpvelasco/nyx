package cli

import (
	"encoding/json"
	"github.com/jpvelasco/nyx/internal/mcp"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/jpvelasco/nyx/internal/snapshot"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestMapDriftTransportParity(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	configureMapFixtures(t)
	old := outputPath
	t.Cleanup(func() { outputPath = old })
	fixtureDir := t.TempDir()
	outputPath = filepath.Join(fixtureDir, "result.json")
	cmd := newMapCaptureCmd()
	cmd.SetContext(t.Context())
	cmd.SetArgs([]string{"before", "--connection", "omada/home", "--skip-tls-verify"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	server := mcp.NewServerWithLogger(nil)
	_, failure := server.DispatchToolForTest(t.Context(), service.MapCaptureTool, map[string]any{"name": "after", "connections": []any{"omada/home"}, "skip_tls_verify": true})
	if failure {
		t.Fatal("MCP capture failed")
	}
	before, err := snapshot.LoadNetworkMapCapture("before")
	if err != nil {
		t.Fatal(err)
	}
	cmd = newMapDriftCmd()
	cmd.SetContext(t.Context())
	cmd.SetArgs([]string{"before", "after"})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	data, err := fs.ReadFile(os.DirFS(fixtureDir), "result.json")
	if err != nil {
		t.Fatal(err)
	}
	var cli snapshot.NetworkDrift
	if err := json.Unmarshal(data, &cli); err != nil {
		t.Fatal(err)
	}
	text, failed := server.DispatchToolForTest(t.Context(), service.MapDriftTool, map[string]any{"before": "before", "after": "after"})
	var env struct {
		Data snapshot.NetworkDrift `json:"data"`
	}
	if failed || json.Unmarshal([]byte(text), &env) != nil || !reflect.DeepEqual(cli, env.Data) {
		t.Fatal("CLI/MCP drift mismatch")
	}
	_, failed = server.DispatchToolForTest(t.Context(), service.MapDriftTool, map[string]any{"before": "before", "skip_tls_verify": true})
	if failed {
		t.Fatal("current-map drift failed")
	}
	after, err := snapshot.LoadNetworkMapCapture("before")
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("baseline changed")
	}
}
