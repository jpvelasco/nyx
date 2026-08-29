package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/credentials"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/jpvelasco/nyx/internal/testutil"
	topology "github.com/jpvelasco/nyx/internal/topology"
)

// topoFlagsRestore snapshots the topology command flag variables so a test
// can set them without leaking into sibling tests (shared package globals).
func topoFlagsRestore(t *testing.T) {
	t.Helper()
	old := struct {
		omadaHost, omadaID, omadaSecret, omadaSite string
		opnsHost, opnsKey, opnsSecret              string
		skipTLS                                    bool
		caCert                                     string
	}{
		topoOmadaHost, topoOmadaClientID, topoOmadaClientSecret, topoOmadaSite,
		topoOpnsenseHost, topoOpnsenseAPIKey, topoOpnsenseAPISecret,
		topoSkipTLSVerify, topoCACertPath,
	}
	t.Cleanup(func() {
		topoOmadaHost, topoOmadaClientID = old.omadaHost, old.omadaID
		topoOmadaClientSecret, topoOmadaSite = old.omadaSecret, old.omadaSite
		topoOpnsenseHost, topoOpnsenseAPIKey = old.opnsHost, old.opnsKey
		topoOpnsenseAPISecret = old.opnsSecret
		topoSkipTLSVerify, topoCACertPath = old.skipTLS, old.caCert
	})
}

// clearTopoEnv blanks every credential env var the topology command reads
// and points the credential store at a guaranteed-empty temp file, so a
// real ~/.nyx/credentials.json on the operator's machine can never leak
// into the assertions. All values are restored at cleanup.
func clearTopoEnv(t *testing.T) {
	t.Helper()
	for _, v := range []string{
		"OMADA_HOST", "OMADA_CLIENT_ID", "OMADA_CLIENT_SECRET", "OMADA_SITE",
		"OPNSENSE_HOST", "OPNSENSE_API_KEY", "OPNSENSE_API_SECRET",
	} {
		t.Setenv(v, "")
	}
	// Point the store at a path that does not exist so Overlay finds nothing.
	t.Setenv("NYX_CREDENTIALS_FILE", t.TempDir()+"/empty-credentials.json")
}

func TestResolveOmadaTopologyOpts_Env(t *testing.T) {
	topoFlagsRestore(t)
	clearTopoEnv(t)
	t.Setenv("OMADA_HOST", "10.0.0.5")
	t.Setenv("OMADA_CLIENT_ID", "u")
	t.Setenv("OMADA_CLIENT_SECRET", "s")
	t.Setenv("OMADA_SITE", "hq")

	opts, err := resolveOmadaTopologyOpts()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts == nil || opts.Host != "10.0.0.5" || opts.ClientID != "u" || opts.Site != "hq" {
		t.Fatalf("opts = %+v, want env mapping", opts)
	}
}

func TestResolveOpnsenseTopologyOpts_Env(t *testing.T) {
	topoFlagsRestore(t)
	clearTopoEnv(t)
	t.Setenv("OPNSENSE_HOST", "10.0.0.9")
	t.Setenv("OPNSENSE_API_KEY", "k")
	t.Setenv("OPNSENSE_API_SECRET", "v")

	opts, err := resolveOpnsenseTopologyOpts()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if opts == nil || opts.Host != "10.0.0.9" || opts.APIKey != "k" {
		t.Fatalf("opts = %+v, want env mapping", opts)
	}
}

func TestResolveTopologyOpts_SkippedWhenNoHost(t *testing.T) {
	topoFlagsRestore(t)
	clearTopoEnv(t)

	omada, err := resolveOmadaTopologyOpts()
	if err != nil {
		t.Fatalf("omada error: %v", err)
	}
	if omada != nil {
		t.Errorf("omada opts = %+v, want nil when no host", omada)
	}
	opns, err := resolveOpnsenseTopologyOpts()
	if err != nil {
		t.Fatalf("opnsense error: %v", err)
	}
	if opns != nil {
		t.Errorf("opnsense opts = %+v, want nil when no host", opns)
	}
}

// A host present with incomplete credentials must be a hard error, not a
// silent skip — a partial picture would mislead the double-NAT verdict.
func TestResolveTopologyOpts_IncompleteCredentialsError(t *testing.T) {
	topoFlagsRestore(t)
	clearTopoEnv(t)
	topoOmadaHost = "10.0.0.5" // host, but no client id/secret anywhere

	omada, err := resolveOmadaTopologyOpts()
	if err == nil {
		t.Fatalf("omada = %+v, want incomplete-credentials error", omada)
	}
	if !strings.Contains(err.Error(), "incomplete") {
		t.Errorf("error %q should name the incomplete credentials", err)
	}

	topoOmadaHost = ""
	topoOpnsenseHost = "10.0.0.9" // host, but no key/secret anywhere
	opns, err := resolveOpnsenseTopologyOpts()
	if err == nil {
		t.Fatalf("opnsense = %+v, want incomplete-credentials error", opns)
	}
	if !strings.Contains(err.Error(), "incomplete") {
		t.Errorf("error %q should name the incomplete credentials", err)
	}
}

func TestResolveTopologyOpts_StoreFallback(t *testing.T) {
	topoFlagsRestore(t)
	clearTopoEnv(t)

	storePath := t.TempDir() + "/credentials.json"
	t.Setenv("NYX_CREDENTIALS_FILE", storePath)
	store, err := credentials.Open(storePath)
	if err != nil {
		t.Fatalf("credentials.Open: %v", err)
	}
	if err := store.Set("omada", "default", credentials.Entry{
		"host":          "10.0.0.5",
		"client_id":     "vault-u",
		"client_secret": "vault-s",
	}); err != nil {
		t.Fatalf("store.Set omada: %v", err)
	}
	if err := store.Set("opnsense", "default", credentials.Entry{
		"host":       "10.0.0.9",
		"api_key":    "vault-k",
		"api_secret": "vault-v",
	}); err != nil {
		t.Fatalf("store.Set opnsense: %v", err)
	}

	omada, err := resolveOmadaTopologyOpts()
	if err != nil {
		t.Fatalf("omada error: %v", err)
	}
	if omada == nil || omada.Host != "10.0.0.5" || omada.ClientID != "vault-u" {
		t.Errorf("omada = %+v, want store values", omada)
	}
	opns, err := resolveOpnsenseTopologyOpts()
	if err != nil {
		t.Fatalf("opnsense error: %v", err)
	}
	if opns == nil || opns.Host != "10.0.0.9" || opns.APIKey != "vault-k" {
		t.Errorf("opnsense = %+v, want store values", opns)
	}
}

// printTopologyReport must render an empty outbound-NAT mode as "unknown"
// (version drift — never guess) and must show both providers' facts.
func TestPrintTopologyReport_UnknownMode(t *testing.T) {
	rep := &service.TopologyReport{
		Risk:   "double_nat",
		Reason: "two devices NAT",
		Devices: []topology.DeviceReport{
			{Provider: "opnsense", Role: topology.RoleBridge, Evidence: []string{"outbound NAT mode is disabled (no automatic source NAT)"}},
		},
		Opnsense: &service.OpnsenseNatSummary{
			OutboundNatMode: "", // key drift → must print "unknown"
		},
		Omada: &service.OmadaNatFacts{Site: "hq", HasManagedGateway: true},
	}
	var buf bytes.Buffer
	printTopologyReport(&buf, rep)
	out := buf.String()
	if !strings.Contains(out, "Double-NAT risk: double_nat") {
		t.Errorf("output missing verdict: %q", out)
	}
	if !strings.Contains(out, "outbound NAT mode:  unknown") {
		t.Errorf("empty mode should print 'unknown': %q", out)
	}
	if !strings.Contains(out, "opnsense: bridge") {
		t.Errorf("output missing per-device role: %q", out)
	}
	if !strings.Contains(out, "managed gateway:    true") {
		t.Errorf("output missing omada facts: %q", out)
	}
}

// topoOpnsenseServer serves the minimal OPNsense NAT-observation endpoints a
// topology RunE success test needs: the outbound-NAT mode plus empty rule
// lists. TLS + basic auth, mirroring the service-layer fixture.
func topoOpnsenseServer(t *testing.T) *httptest.Server {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "key1" || pass != "secret1" {
			w.WriteHeader(http.StatusUnauthorized)
			testutil.WriteBody(w, `{"message":"auth required"}`)
			return
		}
		switch r.URL.Path {
		case "/api/firewall/source_nat/get":
			testutil.WriteBody(w, testutil.SNATModeBody("disabled"))
		case "/api/firewall/d_nat/search_rule",
			"/api/firewall/one_to_one/search_rule",
			"/api/firewall/source_nat/search_rule":
			testutil.WriteBody(w, `{"total":0,"rows":[]}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestTopologyCmd_RunE_NoHost(t *testing.T) {
	saveRestoreGlobals(t)
	topoFlagsRestore(t)
	clearTopoEnv(t)

	rootCmd.SetArgs([]string{"topology"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })
	err := Execute()
	if err == nil {
		t.Fatal("expected error when neither provider has a host")
	}
	if !strings.Contains(err.Error(), "topology needs a host for at least one provider") {
		t.Errorf("error = %v, want host guidance message", err)
	}
}

func TestTopologyCmd_RunE_IncompleteCredentials(t *testing.T) {
	saveRestoreGlobals(t)
	topoFlagsRestore(t)
	clearTopoEnv(t)

	// OPNsense host via flag, no key/secret anywhere → hard error.
	rootCmd.SetArgs([]string{"topology", "--opnsense-host", "10.0.0.9"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })
	err := Execute()
	if err == nil {
		t.Fatal("expected incomplete-credentials error")
	}
	if !strings.Contains(err.Error(), "opnsense credentials incomplete") {
		t.Errorf("error = %v, want opnsense incomplete-credentials message", err)
	}
}

func TestTopologyCmd_RunE_InvalidTimeout(t *testing.T) {
	saveRestoreGlobals(t)
	topoFlagsRestore(t)
	clearTopoEnv(t)
	timeout = "not-a-duration"

	rootCmd.SetArgs([]string{"topology", "--opnsense-host", "10.0.0.9"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })
	err := Execute()
	if err == nil || !strings.Contains(err.Error(), "invalid --timeout") {
		t.Fatalf("error = %v, want invalid --timeout error", err)
	}
}

func TestTopologyCmd_RunE_HumanAndJSON(t *testing.T) {
	saveRestoreGlobals(t)
	topoFlagsRestore(t)
	clearTopoEnv(t)
	ts := topoOpnsenseServer(t)

	// duration 0 → default 60s branch.
	rootCmd.SetArgs([]string{
		"topology",
		"--opnsense-host", ts.URL,
		"--opnsense-api-key", "key1",
		"--opnsense-api-secret", "secret1",
		"--skip-tls-verify",
		"--timeout", "0s",
	})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })

	out := captureStdout(func() {
		if err := Execute(); err != nil {
			t.Fatalf("Execute (human): %v", err)
		}
	})
	for _, want := range []string{
		"Double-NAT risk: none",
		"opnsense: bridge",
		"outbound NAT mode:  disabled",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("human output missing %q:\n%s", want, out)
		}
	}

	// --json variant: the report must round-trip as JSON with the verdict.
	rootCmd.SetArgs([]string{
		"topology",
		"--opnsense-host", ts.URL,
		"--opnsense-api-key", "key1",
		"--opnsense-api-secret", "secret1",
		"--skip-tls-verify",
		"--timeout", "5s",
		"--json",
	})
	jsonOut := captureStdout(func() {
		if err := Execute(); err != nil {
			t.Fatalf("Execute (--json): %v", err)
		}
	})
	var rep service.TopologyReport
	if err := json.Unmarshal([]byte(jsonOut), &rep); err != nil {
		t.Fatalf("json output did not decode: %v\n%s", err, jsonOut)
	}
	if rep.Risk != "none" || len(rep.Devices) != 1 || rep.Opnsense == nil {
		t.Errorf("decoded report = %+v, want risk none + one device + opnsense facts", rep)
	}
	if rep.Opnsense.OutboundNatMode != "disabled" {
		t.Errorf("outbound mode = %q, want disabled", rep.Opnsense.OutboundNatMode)
	}
}

func TestTopologyCmd_RunE_OutputFile(t *testing.T) {
	saveRestoreGlobals(t)
	topoFlagsRestore(t)
	clearTopoEnv(t)
	ts := topoOpnsenseServer(t)

	outFile := fmt.Sprintf("%s/topology.json", t.TempDir())
	rootCmd.SetArgs([]string{
		"topology",
		"--opnsense-host", ts.URL,
		"--opnsense-api-key", "key1",
		"--opnsense-api-secret", "secret1",
		"--skip-tls-verify",
		"--json",
		"--output", outFile,
	})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })
	if err := Execute(); err != nil {
		t.Fatalf("Execute (--output): %v", err)
	}

	// File variant: verify the writer path was taken by reading the file back.
	data, err := os.ReadFile(outFile) // nosemgrep: go_filesystem_rule-fileread — outFile is a fixed name under t.TempDir()
	if err != nil {
		t.Fatalf("output file not written: %v", err)
	}
	var rep service.TopologyReport
	if err := json.Unmarshal(data, &rep); err != nil {
		t.Fatalf("file did not decode: %v\n%s", err, data)
	}
	if rep.Risk != "none" {
		t.Errorf("risk = %q, want none", rep.Risk)
	}
}

func TestTopologyCmd_RunE_OutputFileError(t *testing.T) {
	saveRestoreGlobals(t)
	topoFlagsRestore(t)
	clearTopoEnv(t)
	ts := topoOpnsenseServer(t)

	// A non-existent directory makes getWriter fail after the report is built.
	outFile := fmt.Sprintf("%s/no/such/dir/topology.txt", t.TempDir())
	rootCmd.SetArgs([]string{
		"topology",
		"--opnsense-host", ts.URL,
		"--opnsense-api-key", "key1",
		"--opnsense-api-secret", "secret1",
		"--skip-tls-verify",
		"--output", outFile,
	})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })
	if err := Execute(); err == nil {
		t.Fatal("expected getWriter error for unwritable output path")
	}
}

// A present Omada host with incomplete credentials must fail the command
// before any provider call (RunE's early return after resolveOmadaTopologyOpts).
func TestTopologyCmd_RunE_OmadaIncompleteCredentials(t *testing.T) {
	saveRestoreGlobals(t)
	topoFlagsRestore(t)
	clearTopoEnv(t)

	rootCmd.SetArgs([]string{"topology", "--omada-host", "10.0.0.5"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })
	err := Execute()
	if err == nil || !strings.Contains(err.Error(), "omada credentials incomplete") {
		t.Fatalf("err = %v, want omada-credentials-incomplete", err)
	}
}

// A report fetch failure must propagate as the command's error (RunE's
// early return after TopologyService.Report).
func TestTopologyCmd_RunE_ReportError(t *testing.T) {
	saveRestoreGlobals(t)
	topoFlagsRestore(t)
	clearTopoEnv(t)

	// 404 on every path is a stable error (no retries), so the report
	// fails fast.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		testutil.WriteBody(w, `{"message":"missing"}`)
	}))
	t.Cleanup(ts.Close)

	rootCmd.SetArgs([]string{
		"topology",
		"--opnsense-host", ts.URL,
		"--opnsense-api-key", "key1",
		"--opnsense-api-secret", "secret1",
		"--skip-tls-verify",
	})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })
	err := Execute()
	if err == nil || !strings.Contains(err.Error(), "observing opnsense") {
		t.Fatalf("err = %v, want observing-opnsense prefix", err)
	}
}
