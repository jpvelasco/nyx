package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"github.com/jpvelasco/nyx/internal/service"
	"path/filepath"
	"strings"
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

func TestProviderCapabilitiesHonorsTimeout(t *testing.T) {
	old := timeout
	timeout = "invalid"
	t.Cleanup(func() { timeout = old })
	cmd := providerCapabilitiesCmd()
	cmd.SetArgs([]string{"--observe"})
	if err := cmd.ExecuteContext(t.Context()); err == nil {
		t.Fatal("invalid observation timeout accepted")
	}
}

func TestCapabilitiesOutputAndFiltering(t *testing.T) {
	providerfixture.IsolateProviders(t)
	p := new(providerfixture.ReadOnlyAdapter)
	if err := providers.Register(p); err != nil {
		t.Fatal(err)
	}
	oldJSON, oldTimeout := jsonOutput, timeout
	t.Cleanup(func() { jsonOutput, timeout = oldJSON, oldTimeout })
	timeout = "2s"
	t.Setenv("NYX_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "store.json"))
	t.Setenv("SYNTHETIC_HOST", "switch.example")
	t.Setenv("SYNTHETIC_API_KEY", "fixture-key")
	for _, format := range []bool{false, true} {
		jsonOutput = format
		cmd := providerCapabilitiesCmd()
		cmd.SetArgs([]string{"--provider", "synthetic", "--observe"})
		var out bytes.Buffer
		cmd.SetOut(&out)
		if err := cmd.ExecuteContext(t.Context()); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "observed") || strings.Contains(out.String(), "fixture-key") {
			t.Fatalf("wrong capability output %s", out.String())
		}
		if format {
			var result []service.ProviderCapabilities
			if err := json.Unmarshal(out.Bytes(), &result); err != nil || len(result) != 1 || result[0].Provider != "synthetic" {
				t.Fatal(result, err)
			}
		}
	}
	cmd := providerCapabilitiesCmd()
	cmd.SetArgs([]string{"--provider", "missing"})
	if err := cmd.ExecuteContext(t.Context()); err == nil {
		t.Fatal("accepted missing adapter")
	}
}
