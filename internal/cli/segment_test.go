package cli

import (
	"net/netip"
	"strings"
	"testing"
)

func TestSegmentCLISelectionAndPreview(t *testing.T) {
	t.Setenv("NYX_CREDENTIALS_FILE", t.TempDir()+"/empty.json")
	for _, v := range []string{"OMADA_HOST", "OPNSENSE_HOST"} {
		t.Setenv(v, "")
	}
	root := buildSegmentCmd()
	plan, _, err := root.Find([]string{"plan"})
	if err != nil || plan.Flags().Lookup("dry-run") != nil {
		t.Fatal("plan accepts write flag")
	}
	apply, _, err := root.Find([]string{"apply"})
	if err != nil || apply.Flags().Lookup("dry-run").DefValue != "true" {
		t.Fatal("apply is not a preview by default")
	}
	if err := plan.RunE(plan, nil); err == nil {
		t.Fatal("accepted empty role")
	}
	first := netip.MustParseAddr("10.0.30.1").Next()
	root.SetArgs([]string{"plan", "--role", "gaming", "--parent", "igb0", "--tag", "30", "--gateway", "10.0.30.1/24", "--management-prefix", "10.0.11.0/24", "--resolver", "10.0.40.1", "--pool-start", first.String(), "--pool-end", first.Next().String()})
	root.SilenceUsage = true
	root.SilenceErrors = true
	if err := root.Execute(); err == nil || !strings.Contains(err.Error(), "selected") {
		t.Fatalf("missing controller selection: %v", err)
	}
}
