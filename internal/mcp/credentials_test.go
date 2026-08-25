package mcp

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/credentials"
	"github.com/jpvelasco/nyx/internal/service"
)

// resetEnv clears the environment variables that feed provider credential
// resolution so tests observe the fallback chain deterministically.
func resetEnv(t *testing.T, keys ...string) {
	t.Helper()
	for _, k := range keys {
		t.Setenv(k, "")
	}
}

// omadaEnvKeys are every variable in the Omada credential resolution chain.
func omadaEnvKeys() []string {
	return []string{"OMADA_HOST", "OMADA_CLIENT_ID", "OMADA_CLIENT_SECRET", "OMADA_SITE", "NYX_CREDENTIALS_FILE"}
}

// opnsenseEnvKeys are every variable in the OPNsense credential resolution chain.
func opnsenseEnvKeys() []string {
	return []string{"OPNSENSE_HOST", "OPNSENSE_API_KEY", "OPNSENSE_API_SECRET", "NYX_CREDENTIALS_FILE"}
}

// openTestStore initializes an (empty) store at the path named by
// NYX_CREDENTIALS_FILE and returns that path.
func openTestStore(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credentials.json")
	t.Setenv("NYX_CREDENTIALS_FILE", path)
	if _, err := credentials.Open(path); err != nil {
		t.Fatalf("opening test store: %v", err)
	}
	return path
}

// setStoreEntry writes an entry to the store openTestStore pointed at.
func setStoreEntry(t *testing.T, storePath, provider string, entry credentials.Entry) {
	t.Helper()
	s, err := credentials.Open(storePath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := s.Set(provider, "default", entry); err != nil {
		t.Fatalf("store.Set %s/default: %v", provider, err)
	}
}

// requireToolOK dispatches a tool call and fails the test when it errors.
func requireToolOK(t *testing.T, srv *Server, tool string, args map[string]interface{}) string {
	t.Helper()
	text, isErr := srv.DispatchToolForTest(context.Background(), tool, args)
	if isErr {
		t.Fatalf("%s: unexpected error: %s", tool, text)
	}
	return text
}

// BDD S1.1 — env-var credentials satisfy a host-only Omada call.
func TestMCPToolCallsOmadaCredentialsFromEnv(t *testing.T) {
	resetEnv(t, omadaEnvKeys()...)
	openTestStore(t) // empty store: only the env layer can fill in
	t.Setenv("OMADA_CLIENT_ID", "env-cid")
	t.Setenv("OMADA_CLIENT_SECRET", "env-secret")

	stub := &stubOmadaSvc{inventory: &service.OmadaInventory{Site: "HQ"}}
	requireToolOK(t, serverWithOmadaStub(stub), "omada_inventory", map[string]interface{}{
		"host": "omada.local",
	})
	if stub.calls != 1 {
		t.Fatalf("service calls = %d, want 1", stub.calls)
	}
	if stub.lastOpts.ClientID != "env-cid" || stub.lastOpts.ClientSecret != "env-secret" {
		t.Errorf("options = %+v, want env credentials", stub.lastOpts)
	}
}

// BDD S1.2 — store credentials satisfy a credential-less Omada call (host
// included, env unset).
func TestMCPToolCallsOmadaCredentialsFromStore(t *testing.T) {
	resetEnv(t, omadaEnvKeys()...)
	setStoreEntry(t, openTestStore(t), "omada", credentials.Entry{
		"host":          "stored.omada",
		"client_id":     "store-cid",
		"client_secret": "store-secret",
		"site":          "Stored",
	})

	stub := &stubOmadaSvc{inventory: &service.OmadaInventory{Site: "Stored"}}
	requireToolOK(t, serverWithOmadaStub(stub), "omada_inventory", nil)
	if stub.calls != 1 {
		t.Fatalf("service calls = %d, want 1", stub.calls)
	}
	if stub.lastOpts.Host != "stored.omada" || stub.lastOpts.ClientID != "store-cid" ||
		stub.lastOpts.ClientSecret != "store-secret" || stub.lastOpts.Site != "Stored" {
		t.Errorf("options = %+v, want store credentials", stub.lastOpts)
	}
}

// BDD S1.3 — explicit arguments override env and store.
func TestMCPToolCallsOmadaExplicitArgsWinOverEnvAndStore(t *testing.T) {
	resetEnv(t, omadaEnvKeys()...)
	setStoreEntry(t, openTestStore(t), "omada", credentials.Entry{
		"host":          "stored.omada",
		"client_id":     "store-cid",
		"client_secret": "store-secret",
	})
	t.Setenv("OMADA_HOST", "env.omada")
	t.Setenv("OMADA_CLIENT_ID", "env-cid")
	t.Setenv("OMADA_CLIENT_SECRET", "env-secret")
	t.Setenv("OMADA_SITE", "EnvSite")

	stub := &stubOmadaSvc{inventory: &service.OmadaInventory{Site: "ArgSite"}}
	requireToolOK(t, serverWithOmadaStub(stub), "omada_inventory", map[string]interface{}{
		"host":          "arg.omada",
		"client_id":     "arg-cid",
		"client_secret": "arg-secret",
		"site":          "ArgSite",
	})
	got := stub.lastOpts
	if got.Host != "arg.omada" || got.ClientID != "arg-cid" ||
		got.ClientSecret != "arg-secret" || got.Site != "ArgSite" {
		t.Errorf("options = %+v, want explicit args to win over env and store", got)
	}
}

// BDD S1.4 — credentials missing everywhere keep the actionable error.
func TestMCPToolCallsOmadaCredentialsMissingEverywhere(t *testing.T) {
	resetEnv(t, omadaEnvKeys()...)
	openTestStore(t) // empty store

	server := serverWithOmadaStub(&stubOmadaSvc{})
	text, isErr := server.DispatchToolForTest(context.Background(), "omada_inventory",
		map[string]interface{}{"host": "omada.local"})
	if !isErr {
		t.Fatalf("expected error, got success: %s", text)
	}
	for _, want := range []string{
		"client_id and client_secret parameters are required",
		"OMADA_CLIENT_ID",
		"nyx credentials set omada",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("error = %q, want it to contain %q", text, want)
		}
	}
}

// BDD S2.1 — env-var or store credentials satisfy OPNsense calls.
func TestMCPToolCallsOpnsenseCredentialsFromEnv(t *testing.T) {
	resetEnv(t, opnsenseEnvKeys()...)
	openTestStore(t)
	t.Setenv("OPNSENSE_API_KEY", "env-key")
	t.Setenv("OPNSENSE_API_SECRET", "env-secret")

	stub := &stubOpnsenseSvc{info: &service.OpnsenseInfo{Provider: "opnsense", Version: "24.7.11"}}
	requireToolOK(t, serverWithOpnsenseStub(stub), "opnsense_get_info", map[string]interface{}{
		"host": "fw.local",
	})
	if stub.lastOpts.APIKey != "env-key" || stub.lastOpts.APISecret != "env-secret" {
		t.Errorf("options = %+v, want env credentials", stub.lastOpts)
	}
}

func TestMCPToolCallsOpnsenseCredentialsFromStore(t *testing.T) {
	resetEnv(t, opnsenseEnvKeys()...)
	setStoreEntry(t, openTestStore(t), "opnsense", credentials.Entry{
		"host":       "stored.fw",
		"api_key":    "store-key",
		"api_secret": "store-secret",
	})

	stub := &stubOpnsenseSvc{info: &service.OpnsenseInfo{Provider: "opnsense"}}
	requireToolOK(t, serverWithOpnsenseStub(stub), "opnsense_get_info", nil)
	if stub.lastOpts.Host != "stored.fw" || stub.lastOpts.APIKey != "store-key" ||
		stub.lastOpts.APISecret != "store-secret" {
		t.Errorf("options = %+v, want store credentials", stub.lastOpts)
	}
}

// BDD S2.2 — missing OPNsense credentials keep the actionable error.
func TestMCPToolCallsOpnsenseCredentialsMissingEverywhere(t *testing.T) {
	resetEnv(t, opnsenseEnvKeys()...)
	openTestStore(t) // empty store

	server := serverWithOpnsenseStub(&stubOpnsenseSvc{})
	text, isErr := server.DispatchToolForTest(context.Background(), "opnsense_get_info",
		map[string]interface{}{"host": "fw.local"})
	if !isErr {
		t.Fatalf("expected error, got success: %s", text)
	}
	for _, want := range []string{
		"api_key and api_secret parameters are required",
		"OPNSENSE_API_KEY",
		"nyx credentials set opnsense",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("error = %q, want it to contain %q", text, want)
		}
	}
}
