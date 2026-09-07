package cli

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
)

func saveRestoreFetchCert(t *testing.T) {
	t.Helper()
	saveRestoreGlobals(t)
	oldHost, oldOut, oldForce := fetchCertHost, fetchCertOut, fetchCertForce
	t.Cleanup(func() {
		fetchCertHost, fetchCertOut, fetchCertForce = oldHost, oldOut, oldForce
	})
	fetchCertHost, fetchCertOut, fetchCertForce = "", "", false
}

func TestFetchCertCmd_MissingOut(t *testing.T) {
	saveRestoreFetchCert(t)
	cmd := buildFetchCertCmd("omada")
	fetchCertHost = "127.0.0.1"
	if err := cmd.RunE(cmd, nil); err == nil || !strings.Contains(err.Error(), "--out is required") {
		t.Fatalf("error = %v, want --out required", err)
	}
}

func TestFetchCertCmd_MissingHost(t *testing.T) {
	saveRestoreFetchCert(t)
	t.Setenv("OMADA_HOST", "")
	cmd := buildFetchCertCmd("omada")
	fetchCertOut = filepath.Join(t.TempDir(), "ca.pem")
	if err := cmd.RunE(cmd, nil); err == nil || !strings.Contains(err.Error(), "host is required") {
		t.Fatalf("error = %v, want host required", err)
	}
}

func TestFetchCertCmd_WritesPEM(t *testing.T) {
	saveRestoreFetchCert(t)
	url, _ := testutil.CASignedServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	out := filepath.Join(t.TempDir(), "ca.pem")
	cmd := buildFetchCertCmd("omada")
	fetchCertHost = strings.TrimPrefix(url, "https://")
	fetchCertOut = out
	got := captureStdout(func() {
		if err := cmd.RunE(cmd, nil); err != nil {
			t.Fatalf("fetch-cert: %v", err)
		}
	})
	if !strings.Contains(got, "wrote "+out) || !strings.Contains(got, "certs") {
		t.Errorf("stdout = %q, want wrote <path> (N certs)", got)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("expected PEM at %s: %v", out, err)
	}
}

func TestFetchCertCmd_WiredOnBothVendors(t *testing.T) {
	// The helper is extra (non-capability) surface; look it up on a
	// freshly built vendor command rather than on the process-global
	// root, which other tests may already have mutated.
	for _, vendor := range []string{"omada", "opnsense"} {
		cmd := buildFetchCertCmd(vendor)
		if cmd.Use != "fetch-cert" {
			t.Errorf("%s fetch-cert Use = %q", vendor, cmd.Use)
		}
		if cmd.Flags().Lookup("out") == nil || cmd.Flags().Lookup("host") == nil {
			t.Errorf("%s fetch-cert missing --host/--out", vendor)
		}
	}
}
