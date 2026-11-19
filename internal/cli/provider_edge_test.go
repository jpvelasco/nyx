package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildInventoryCmdSegmentEdges(t *testing.T) {
	saveRestoreGlobals(t)
	clearProviderEnv(t)
	path := filepath.Join(t.TempDir(), "spec.yaml")
	if err := os.WriteFile(path, []byte(`version: 1
site: example
networks:
  - name: trusted
    cidr: 10.0.10.0/24
    edge: opnsense
    observer: omada
`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		json bool
		want string
	}{
		{false, "trusted: edge=opnsense observer=omada"},
		{true, `"observer": "omada"`},
	} {
		cmd := buildInventoryCmd(&fakeProvider{name: "fake"})
		jsonOutput = tc.json
		cmd.SetArgs([]string{"--host", "inventory.example", "--spec", path})
		output := captureStdout(func() {
			if err := cmd.Execute(); err != nil {
				t.Error(err)
			}
		})
		if !strings.Contains(output, tc.want) {
			t.Errorf("output=%q missing %q", output, tc.want)
		}
	}
	cmd := buildInventoryCmd(&fakeProvider{name: "fake"})
	cmd.SetArgs([]string{"--spec", path + ".missing"})
	if err := cmd.Execute(); err == nil {
		t.Fatal("expected missing spec error")
	}
}
