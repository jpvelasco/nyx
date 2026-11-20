package cli

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/testutil"
	"github.com/jpvelasco/nyx/internal/topology"
)

func draftFixture() *topology.Fingerprint {
	return &topology.Fingerprint{
		Segments: []topology.FingerprintSegment{
			{VLAN: 10, Gateway: "omada", ObservedBy: []string{"omada"}, Detail: &topology.SegmentDetail{
				CIDR: "10.0.10.0/24", GatewayAddress: "10.0.10.1",
				ProbeCandidates: []topology.ProbeCandidate{{Address: "10.0.10.30", Hostname: "desk", Source: "omada"}},
			}},
			{VLAN: 60, Gateway: "opnsense", ObservedBy: []string{"opnsense"}, Detail: &topology.SegmentDetail{
				CIDR: "10.0.60.0/24", GatewayAddress: "10.0.60.1",
				ProbeCandidates: []topology.ProbeCandidate{{Address: "10.0.60.7", Hostname: "cam", Source: "opnsense"}},
			}},
			{VLAN: 99, ObservedBy: []string{"opnsense"}}, // no subnet observed
		},
		Matrix: &topology.EnforcementMatrix{Pairs: []topology.MatrixPair{
			{From: 10, To: 60, PairSpecific: true},
			{From: 60, To: 10}, // no pair-specific rule
		}},
	}
}

// readDraftFile reads a draft the test itself wrote under t.TempDir().
func readDraftFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path) // nosemgrep: go_filesystem_rule-fileread — path is a fixed name under t.TempDir()
	if err != nil {
		t.Fatalf("reading draft: %v", err)
	}
	return string(data)
}

func TestRenderDraftSpecRoundTrips(t *testing.T) {
	draft := renderDraftSpec(draftFixture(), []string{"10.0.10.0/24"})
	spec, err := intent.ParseSpec(draft)
	if err != nil {
		t.Fatalf("draft does not validate: %v\n%s", err, draft)
	}
	if len(spec.Networks) != 2 {
		t.Fatalf("networks = %+v, want vlan10 and vlan60", spec.Networks)
	}
	want := intent.Network{Name: "vlan10", CIDR: "10.0.10.0/24", Gateway: "10.0.10.1", Zone: "vlan10", VLAN: 10}
	if spec.Networks[0] != want {
		t.Errorf("network[0] = %+v, want %+v", spec.Networks[0], want)
	}
	// Probes and isolation assertions are suggestions only: commented out.
	if len(spec.Probes) != 0 || len(spec.Assertions) != 0 {
		t.Errorf("probes = %+v, assertions = %+v; want suggestions left commented", spec.Probes, spec.Assertions)
	}
}

func TestRenderDraftSpecSuggestions(t *testing.T) {
	draft := string(renderDraftSpec(draftFixture(), []string{"10.0.10.0/24"}))
	for _, want := range []string{
		"zone: vlan10 # TODO: set the zone role (docs/naming.md)",
		"# vantage: this machine is attached to vlan10",
		"# edge: omada # fingerprint: omada serves this VLAN's gateway",
		"# VLAN 99: observed by opnsense, but no subnet was observed; add it by hand",
		"#   - name: vlan60-probe\n#     host: 10.0.60.7 # candidate from opnsense inventory (cam); unverified\n#     user: <your-user>\n#     vlan: vlan60",
		"#   - type: isolation\n#     from: vlan60\n#     to: vlan10\n#     expect: deny # TODO: no rule names vlan60 -> vlan10; confirm the intended verdict",
	} {
		if !strings.Contains(draft, want) {
			t.Errorf("draft is missing %q:\n%s", want, draft)
		}
	}
	// The vantage segment needs no probe; only other segments get one.
	if strings.Contains(draft, "vlan10-probe") {
		t.Errorf("vantage segment got a probe suggestion:\n%s", draft)
	}
	// A pair that has a pair-specific rule gets no suggestion.
	if strings.Contains(draft, "no rule names vlan10 -> vlan60") {
		t.Errorf("covered pair got an isolation suggestion:\n%s", draft)
	}
}

func TestWriteDraftSpecRefusesOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "draft.yaml")
	if err := os.WriteFile(path, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := writeDraftSpec(path, []byte("version: 1\n"), false)
	if err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("err = %v, want refusal that mentions --force", err)
	}
	if got := readDraftFile(t, path); got != "keep me" {
		t.Fatalf("existing file was modified: %q", got)
	}
	if err := writeDraftSpec(path, []byte("version: 1\n"), true); err != nil {
		t.Fatalf("--force write: %v", err)
	}
	if got := readDraftFile(t, path); got != "version: 1\n" {
		t.Fatalf("forced write = %q", got)
	}
}

func TestTopologyCmd_RunE_DraftSpec(t *testing.T) {
	saveRestoreGlobals(t)
	topoFlagsRestore(t)
	clearTopoEnv(t)
	t.Cleanup(func() {
		for _, name := range []string{"draft-spec", "force", "fingerprint", "detail", "matrix"} {
			_ = topologyCmd.Flags().Set(name, topologyCmd.Flags().Lookup(name).DefValue)
		}
	})
	prevVantage := localVantageCIDRs
	localVantageCIDRs = func() []string { return []string{"10.0.10.0/24"} }
	t.Cleanup(func() { localVantageCIDRs = prevVantage })

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/firewall/source_nat/get":
			testutil.WriteBody(w, testutil.SNATModeBody("automatic"))
		case "/api/firewall/d_nat/search_rule", "/api/firewall/one_to_one/search_rule", "/api/firewall/source_nat/search_rule",
			"/api/interfaces/bridge_settings/search_item":
			testutil.WriteBody(w, `{"total":0,"rows":[]}`)
		case "/api/interfaces/overview/interfaces_info":
			testutil.WriteBody(w, `{"rows":[
				{"identifier":"opt1","addr4":"10.0.10.1/24","device":"vlan01"},
				{"identifier":"opt6","addr4":"10.0.60.1/24","device":"vlan06"}]}`)
		case "/api/interfaces/vlan_settings/search_item":
			testutil.WriteBody(w, `{"total":2,"rows":[{"uuid":"f1","tag":"10","vlanif":"vlan01"},{"uuid":"f6","tag":"60","vlanif":"vlan06"}]}`)
		case "/api/firewall/filter/search_rule":
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"r1","enabled":"1","action":"block","interface":"opt6","source_net":"opt6","destination_net":"opt1"}]}`)
		case "/api/dnsmasq/settings/get":
			testutil.WriteBody(w, `{"dnsmasq":{"enable":"1"}}`)
		case "/api/dnsmasq/leases/search":
			testutil.WriteBody(w, `{"leases":[{"mac":"aa:bb:cc:dd:ee:06","ip":"10.0.60.7","hostname":"cam"}]}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	t.Cleanup(ts.Close)

	path := filepath.Join(t.TempDir(), "draft.yaml")
	args := []string{"topology", "--opnsense-host", ts.URL, "--opnsense-api-key", "key1", "--opnsense-api-secret", "secret1",
		"--skip-tls-verify", "--draft-spec", path}
	rootCmd.SetArgs(args)
	t.Cleanup(func() { rootCmd.SetArgs(nil) })
	var stderr bytes.Buffer
	rootCmd.SetErr(&stderr)
	t.Cleanup(func() { rootCmd.SetErr(nil) })
	_ = captureStdout(func() {
		if err := Execute(); err != nil {
			t.Fatalf("Execute (--draft-spec): %v", err)
		}
	})

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("draft not written: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("draft mode = %v, want 0600 (it holds private addresses)", info.Mode().Perm())
	}
	data := []byte(readDraftFile(t, path))
	spec, err := intent.ParseSpec(data)
	if err != nil {
		t.Fatalf("written draft does not validate: %v\n%s", err, data)
	}
	if len(spec.Networks) != 2 || !strings.Contains(string(data), "# vantage: this machine is attached to vlan10") ||
		!strings.Contains(string(data), "#     host: 10.0.60.7") || !strings.Contains(string(data), "#     from: vlan10\n#     to: vlan60") {
		t.Errorf("draft content:\n%s", data)
	}
	if !strings.Contains(stderr.String(), "contains private addresses") {
		t.Errorf("stderr = %q, want the private-address notice", stderr.String())
	}

	// A second run must not overwrite the draft without --force.
	if err := Execute(); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("second run err = %v, want overwrite refusal", err)
	}
}

func TestRenderDraftSpecEdgeCases(t *testing.T) {
	t.Run("no matrix: no isolation suggestions", func(t *testing.T) {
		fp := draftFixture()
		fp.Matrix = nil
		if draft := string(renderDraftSpec(fp, nil)); strings.Contains(draft, "type: isolation") {
			t.Fatalf("draft without a matrix has isolation suggestions:\n%s", draft)
		}
	})
	t.Run("pair with an undrafted segment is skipped", func(t *testing.T) {
		fp := draftFixture()
		fp.Matrix.Pairs = append(fp.Matrix.Pairs, topology.MatrixPair{From: 60, To: 99}) // VLAN 99 has no subnet
		if draft := string(renderDraftSpec(fp, nil)); strings.Contains(draft, "vlan99") {
			t.Fatalf("draft names undrafted vlan99:\n%s", draft)
		}
	})
	t.Run("unparseable vantage CIDR is ignored", func(t *testing.T) {
		draft := string(renderDraftSpec(draftFixture(), []string{"not-a-cidr"}))
		if strings.Contains(draft, "# vantage:") {
			t.Fatalf("garbage vantage CIDR produced a marker:\n%s", draft)
		}
		// With no vantage, every segment with a candidate gets a probe.
		if !strings.Contains(draft, "vlan10-probe") || !strings.Contains(draft, "vlan60-probe") {
			t.Fatalf("missing probe suggestions without a vantage:\n%s", draft)
		}
	})
}

// TestLocalVantageCIDRs runs the real detector (the other tests stub it):
// whatever this host is attached to must come back as parseable prefixes.
func TestLocalVantageCIDRs(t *testing.T) {
	for _, cidr := range localVantageCIDRs() {
		if !maskedPrefix(cidr).IsValid() {
			t.Errorf("local vantage %q is not a CIDR", cidr)
		}
	}
}
