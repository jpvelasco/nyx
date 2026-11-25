package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/credentials"
	"github.com/jpvelasco/nyx/internal/credentials/credmanager"
	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// fakeWMReader is a controllable Credential Manager reader for
// providerImportOptions overlay tests.
type fakeWMReader struct {
	cred     credmanager.Cred
	found    bool
	target   string
	readCall int
}

func (f *fakeWMReader) Read(target string) (credmanager.Cred, bool, error) {
	f.readCall++
	f.target = target
	return f.cred, f.found, nil
}

// clearProviderEnv clears the env var names of both known providers so the
// tests exercise the store/flag layers even when the machine happens to have
// OMADA_* or OPNSENSE_* exported.
func clearProviderEnv(t *testing.T) {
	t.Helper()
	for _, provider := range []string{"omada", "opnsense"} {
		for _, field := range credentials.FieldsFor(provider) {
			n := field.Env
			if n != "" {
				t.Setenv(n, "")
			}
		}
	}
}

// writeCredentialStore stores a provider entry in a temp store and points
// NYX_CREDENTIALS_FILE at it, so providerImportOptions sees a real (empty or
// seeded) store without touching ~/.nyx.
func writeCredentialStore(t *testing.T, provider string, entry credentials.Entry) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credentials.json")
	t.Setenv("NYX_CREDENTIALS_FILE", path)
	if entry == nil {
		return
	}
	store, err := credentials.Open(path)
	if err != nil {
		t.Fatalf("opening temp credential store: %v", err)
	}
	if err := store.Set(provider, "default", entry); err != nil {
		t.Fatalf("seeding credential store: %v", err)
	}
}

func TestProviderImportOptions_UnknownProviderIsolated(t *testing.T) {
	saveRestoreGlobals(t)
	clearProviderEnv(t)
	writeCredentialStore(t, "omada", nil)
	t.Setenv("OMADA_HOST", "controller.example")
	t.Setenv("OMADA_CLIENT_SECRET", "example-secret")
	opts := providerImportOptions("fake")
	if opts.Host != "" || opts.ClientID != "" || opts.ClientSecret != "" {
		t.Fatal("unregistered adapter inherited Omada fields")
	}
}

func TestProviderImportOptions_OpnsenseEnv(t *testing.T) {
	saveRestoreGlobals(t)
	clearProviderEnv(t)
	t.Setenv("OPNSENSE_HOST", "10.0.11.1")
	t.Setenv("OPNSENSE_API_KEY", "env-key")
	t.Setenv("OPNSENSE_API_SECRET", "env-secret")

	opts := providerImportOptions("opnsense")
	if opts.Host != "10.0.11.1" {
		t.Errorf("Host = %q, want OPNSENSE_HOST", opts.Host)
	}
	if opts.ClientID != "env-key" {
		t.Errorf("ClientID = %q, want OPNSENSE_API_KEY", opts.ClientID)
	}
	if opts.ClientSecret != "env-secret" {
		t.Errorf("ClientSecret = %q, want OPNSENSE_API_SECRET", opts.ClientSecret)
	}
}

func TestProviderImportOptions_OpnsenseStore(t *testing.T) {
	saveRestoreGlobals(t)
	clearProviderEnv(t)
	writeCredentialStore(t, "opnsense", credentials.Entry{
		"host":       "10.0.11.2",
		"api_key":    "store-key",
		"api_secret": "store-secret",
	})

	opts := providerImportOptions("opnsense")
	if opts.Host != "10.0.11.2" {
		t.Errorf("Host = %q, want store host", opts.Host)
	}
	if opts.ClientID != "store-key" {
		t.Errorf("ClientID = %q, want store api_key", opts.ClientID)
	}
	if opts.ClientSecret != "store-secret" {
		t.Errorf("ClientSecret = %q, want store api_secret", opts.ClientSecret)
	}
}

func TestProviderImportOptions_OpnsenseWMOverlay(t *testing.T) {
	saveRestoreGlobals(t)
	clearProviderEnv(t)
	writeCredentialStore(t, "opnsense", nil) // empty store: only WM can fill
	providerHost = "fw.example"
	t.Cleanup(func() { credmanager.SetReader(nil) })

	f := &fakeWMReader{cred: credmanager.Cred{ClientID: "wm-key", ClientSecret: "wm-secret"}, found: true}
	credmanager.SetReader(f)

	opts := providerImportOptions("opnsense")
	if opts.ClientID != "wm-key" || opts.ClientSecret != "wm-secret" {
		t.Fatalf("creds = %q/%q, want WM values", opts.ClientID, opts.ClientSecret)
	}
	if f.target != "nyx-opnsense-fw.example" {
		t.Fatalf("target = %q, want nyx-opnsense-fw.example", f.target)
	}
	if opts.Host != "fw.example" {
		t.Fatalf("Host = %q, want flag host (WM must never supply the host)", opts.Host)
	}
}

func TestProviderImportOptions_OpnsenseEnvWinsOverWM(t *testing.T) {
	saveRestoreGlobals(t)
	clearProviderEnv(t)
	writeCredentialStore(t, "opnsense", nil)
	providerHost = "fw.example"
	t.Setenv("OPNSENSE_API_KEY", "env-key")
	t.Setenv("OPNSENSE_API_SECRET", "env-secret")
	t.Cleanup(func() { credmanager.SetReader(nil) })

	f := &fakeWMReader{cred: credmanager.Cred{ClientID: "wm-key", ClientSecret: "wm-secret"}, found: true}
	credmanager.SetReader(f)

	opts := providerImportOptions("opnsense")
	if opts.ClientID != "env-key" || opts.ClientSecret != "env-secret" {
		t.Fatalf("creds = %q/%q, want env values over WM", opts.ClientID, opts.ClientSecret)
	}
}

func TestProviderImportOptions_OpnsenseFlagOverridesStore(t *testing.T) {
	saveRestoreGlobals(t)
	clearProviderEnv(t)
	writeCredentialStore(t, "opnsense", credentials.Entry{
		"host":       "10.0.11.2",
		"api_key":    "store-key",
		"api_secret": "store-secret",
	})
	providerHost = "10.0.11.3"
	providerClientID = "flag-key"
	providerClientSecret = "flag-secret"

	opts := providerImportOptions("opnsense")
	if opts.Host != "10.0.11.3" {
		t.Errorf("Host = %q, want flag value", opts.Host)
	}
	if opts.ClientID != "flag-key" || opts.ClientSecret != "flag-secret" {
		t.Errorf("flag creds = %q/%q, want flag values", opts.ClientID, opts.ClientSecret)
	}
}

func TestProviderImportOptions_OmadaStoreUnchanged(t *testing.T) {
	saveRestoreGlobals(t)
	clearProviderEnv(t)
	writeCredentialStore(t, "omada", credentials.Entry{
		"host":          "10.0.11.4",
		"client_id":     "omada-user",
		"client_secret": "omada-pass",
		"api_key":       "leftover-key",
		"api_secret":    "leftover-secret",
	})

	opts := providerImportOptions("omada")
	if opts.Host != "10.0.11.4" {
		t.Errorf("Host = %q, want store host", opts.Host)
	}
	if opts.ClientID != "omada-user" {
		t.Errorf("ClientID = %q, want store client_id, not api_key", opts.ClientID)
	}
	if opts.ClientSecret != "omada-pass" {
		t.Errorf("ClientSecret = %q, want store client_secret, not api_secret", opts.ClientSecret)
	}
}

func TestRequireProviderHost_Opnsense(t *testing.T) {
	err := requireProviderHost(providers.ImportOptions{}, "opnsense")
	if err == nil {
		t.Fatal("expected missing-host error")
	}
	msg := err.Error()
	for _, want := range []string{"OPNSENSE_HOST", "OPNSENSE_API_KEY", "OPNSENSE_API_SECRET", "opnsense"} {
		if !strings.Contains(msg, want) {
			t.Errorf("error %q does not name %s", msg, want)
		}
	}
}

func TestRequireProviderHost_UnknownProviderOmitsOmadaNames(t *testing.T) {
	err := requireProviderHost(providers.ImportOptions{}, "fake")
	if err == nil {
		t.Fatal("expected missing-host error")
	}
	if strings.Contains(err.Error(), "OMADA_HOST") {
		t.Error("unknown provider advertised Omada credentials")
	}
}

func TestRequireProviderHost_ResolvedHostPasses(t *testing.T) {
	for _, name := range []string{"omada", "opnsense", "fake"} {
		if err := requireProviderHost(providers.ImportOptions{Host: "10.0.11.1"}, name); err != nil {
			t.Errorf("requireProviderHost(%q) with resolved host = %v, want nil", name, err)
		}
	}
}

func TestProviderCredFlags_OmadaVsOpnsense(t *testing.T) {
	// Look up flags on built cobra commands. Existing providerImportOptions
	// tests keep setting the package vars, not flag names.
	cases := []struct {
		name        string
		cmd         *cobra.Command
		wantPresent []string
		wantAbsent  []string
		wantHelp    map[string]string
	}{
		{
			name:        "omada info",
			cmd:         buildInfoCmd(&fakeProvider{name: "omada"}),
			wantPresent: []string{"host", "client-id", "client-secret"},
			wantAbsent:  []string{"api-key", "api-secret"},
			wantHelp: map[string]string{
				"client-id":     "Omada Open API client ID",
				"client-secret": "Omada Open API client secret",
			},
		},
		{
			name:        "opnsense info",
			cmd:         buildInfoCmd(&fakeProvider{name: "opnsense"}),
			wantPresent: []string{"host", "api-key", "api-secret"},
			wantAbsent:  []string{"client-id", "client-secret"},
			wantHelp: map[string]string{
				"api-key":    "OPNsense API key",
				"api-secret": "OPNsense API secret",
			},
		},
		{
			name:        "opnsense import",
			cmd:         buildImportCmd(&fakeProvider{name: "opnsense"}),
			wantPresent: []string{"api-key", "api-secret"},
			wantAbsent:  []string{"client-id", "client-secret"},
		},
		{
			name:        "opnsense check",
			cmd:         buildCheckCmd(&fakeProvider{name: "opnsense"}),
			wantPresent: []string{"api-key", "api-secret"},
			wantAbsent:  []string{"client-id", "client-secret"},
		},
		{
			name:        "opnsense inventory",
			cmd:         buildInventoryCmd(&fakeProvider{name: "opnsense"}),
			wantPresent: []string{"api-key", "api-secret"},
			wantAbsent:  []string{"client-id", "client-secret"},
		},
		{
			name:        "unknown provider has no vendor credential flags",
			cmd:         buildInfoCmd(&fakeProvider{name: "fake"}),
			wantPresent: []string{"host", "profile"},
			wantAbsent:  []string{"client-id", "client-secret", "api-key", "api-secret"},
		},
		{
			name:        "omada extra uplink-info",
			cmd:         buildOmadaUplinkInfoCmd(),
			wantPresent: []string{"client-id", "client-secret"},
			wantAbsent:  []string{"api-key", "api-secret"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertProviderCredFlags(t, tc.cmd.Flags(), tc.wantPresent, tc.wantAbsent, tc.wantHelp)
		})
	}
}

func TestProviderCredFlags_OpnsenseBindsToSharedVars(t *testing.T) {
	saveRestoreGlobals(t)
	cmd := buildInfoCmd(&fakeProvider{name: "opnsense"})
	if err := cmd.ParseFlags([]string{"--host", "10.0.11.1", "--api-key", "k", "--api-secret", "s"}); err != nil {
		t.Fatalf("ParseFlags: %v", err)
	}
	if providerHost != "10.0.11.1" || providerClientID != "k" || providerClientSecret != "s" {
		t.Errorf("bound vars = host=%q id=%q secret=%q, want 10.0.11.1/k/s",
			providerHost, providerClientID, providerClientSecret)
	}
}

func assertProviderCredFlags(t *testing.T, flags *pflag.FlagSet, present, absent []string, help map[string]string) {
	t.Helper()
	for _, name := range present {
		if flags.Lookup(name) == nil {
			t.Errorf("missing flag --%s", name)
		}
	}
	for _, name := range absent {
		if flags.Lookup(name) != nil {
			t.Errorf("unexpected flag --%s", name)
		}
	}
	for name, want := range help {
		f := flags.Lookup(name)
		if f == nil {
			continue
		}
		if f.Usage != want {
			t.Errorf("--%s help = %q, want %q", name, f.Usage, want)
		}
	}
}

type singleKeyController struct {
	fakeProvider
	received string
}

func (p *singleKeyController) CredentialFields() []credentials.Field {
	return []credentials.Field{{Name: "host", Required: true}, {Name: "token", Required: true, Secret: true, Env: "SENSOR_TOKEN"}}
}
func (p *singleKeyController) Info(_ context.Context, opts providers.ImportOptions) (*providers.ProviderInfo, error) {
	p.received = opts.Credentials["token"]
	return nil, fmt.Errorf("adapter rejected %s", p.received)
}
func TestThirdProviderCredentialFlagsAndErrors(t *testing.T) {
	saveRestoreGlobals(t)
	p := &singleKeyController{fakeProvider: fakeProvider{name: "sensor"}}
	if err := providers.Register(p); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(providers.Reset)
	writeCredentialStore(t, "omada", nil)
	t.Setenv("SENSOR_TOKEN", "ambient-fixture")
	cmd := buildInfoCmd(p)
	if err := cmd.ParseFlags([]string{"--profile", "trusted", "--host", "sensor.example"}); err != nil {
		t.Fatal(err)
	}
	if err := cmd.RunE(cmd, nil); err == nil || !strings.Contains(err.Error(), "missing required fields: token") || p.received != "" {
		t.Fatal("incomplete profile used ambient credentials")
	}
	if err := cmd.ParseFlags([]string{"--token", "explicit-fixture"}); err != nil {
		t.Fatal(err)
	}
	if err := cmd.RunE(cmd, nil); err == nil || err.Error() != "adapter rejected [redacted]" || p.received != "explicit-fixture" {
		t.Fatal("failed to pass the adapter its own credential or scrub its error")
	}
}
