package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/credentials"
	"github.com/jpvelasco/nyx/internal/service"
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
