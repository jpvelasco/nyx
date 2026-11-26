package cli

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/testutil/providerfixture"
	"github.com/spf13/cobra"
)

func TestRegisteredInfoOnlyAdapterCLI(t *testing.T) {
	providerfixture.IsolateProviders(t)
	p := new(providerfixture.ReadOnlyAdapter)
	if err := providers.Register(p); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NYX_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials.json"))
	prev := jsonOutput
	jsonOutput = true
	t.Cleanup(func() { jsonOutput = prev })
	root := &cobra.Command{Use: "nyx"}
	BuildProviderSubcommands(root)
	root.SetArgs([]string{"synthetic", "info", "--host", "switch.example", "--api-key", "fixture"})
	out := captureStdout(func() {
		if err := root.ExecuteContext(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
	var info providers.ProviderInfo
	if err := json.Unmarshal([]byte(out), &info); err != nil || info.Provider != "synthetic" || info.Host != "switch.example" || p.Calls != 1 {
		t.Fatalf("unexpected controller read: %v %v %d", info, err, p.Calls)
	}
}
