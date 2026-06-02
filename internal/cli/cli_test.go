package cli

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	// Blank imports trigger provider init() so BuildProviderSubcommands sees them in tests
	_ "github.com/jpvelasco/nyx/internal/providers/omada"
	_ "github.com/jpvelasco/nyx/internal/providers/opnsense"
)

func TestGetSelectedInterface(t *testing.T) {
	// default empty
	interfaceOpt = ""
	if got := GetSelectedInterface(); got != "" {
		t.Errorf("default = %q, want empty", got)
	}
	interfaceOpt = "eth0"
	if got := GetSelectedInterface(); got != "eth0" {
		t.Errorf("got %q", got)
	}
	// reset for other tests
	interfaceOpt = ""
}

func TestVersionCmdOutput(t *testing.T) {
	// versionCmd uses fmt.Printf directly (not cmd.Out), so capture os.Stdout.
	// Call Run directly to avoid cobra Execute side-effects on an unattached leaf command.
	out := captureStdout(func() {
		versionCmd.Run(versionCmd, []string{})
	})
	if !strings.Contains(out, "nyx v") {
		t.Errorf("version output missing 'nyx v': %q", out)
	}
}

// captureStdout runs f while temporarily redirecting os.Stdout and returns what was written.
func captureStdout(f func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	f()
	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	return buf.String()
}

func TestRootHelpContainsCommands(t *testing.T) {
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--help"})
	// Execute may call os.Exit on some errors but help should be fine (SilenceUsage true)
	_ = rootCmd.Execute()
	out := buf.String()
	if !strings.Contains(out, "audit") || !strings.Contains(out, "discover") {
		t.Errorf("help missing expected commands: %s", out)
	}
}

func TestGetWriterStdoutDefault(t *testing.T) {
	outputPath = ""
	f, err := getWriter()
	if err != nil {
		t.Fatal(err)
	}
	if f != os.Stdout {
		t.Error("expected stdout when no --output")
	}
}

func TestGetWriterFile(t *testing.T) {
	tmp := t.TempDir() + "/out.txt"
	outputPath = tmp
	defer func() { outputPath = "" }()

	f, err := getWriter()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if f == os.Stdout {
		t.Error("expected file, not stdout")
	}
}

// smoke: ensure provider subcommands get built (they are added in Execute)
func TestBuildProviderSubcommandsAddsVendors(t *testing.T) {
	// fresh root to avoid double add in test
	fresh := &cobra.Command{Use: "nyx"}
	BuildProviderSubcommands(fresh)

	// look for omada or opnsense subcommand
	found := false
	for _, c := range fresh.Commands() {
		if c.Use == "omada" || c.Use == "opnsense" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected provider subcommands (omada/opnsense) after BuildProviderSubcommands")
	}
}
