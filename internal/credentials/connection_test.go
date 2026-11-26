package credentials

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestNamedConnectionIsolation(t *testing.T) {
	store, path := newTestStore(t)
	for profile, entry := range map[string]Entry{
		"default": {"host": "default.example", "api_key": "default-key", "api_secret": "default-secret"},
		"one":     {"host": "one.example", "api_key": "one-key", "api_secret": "one-secret", "logical_site": "trusted"},
		"two":     {"host": "two.example", "api_key": "two-key"},
	} {
		if err := store.Set("opnsense", profile, entry); err != nil {
			t.Fatal(err)
		}
	}
	getenv := func(string) string { return "ambient-value" }
	c := Connection{Provider: "opnsense", Profile: "two"}
	got := Resolve(c, nil, getenv, path, true)
	if got["host"] != "two.example" || got["api_key"] != "two-key" || got["api_secret"] != "" {
		t.Fatal("incomplete profile inherited credentials")
	}
	c.Profile = "one"
	if got = Resolve(c, Entry{"host": "two.example"}, getenv, path, true); got["api_secret"] != "" {
		t.Fatal("retargeted named connection reused credentials")
	}
	got = Resolve(c, nil, getenv, path, false)
	if got["host"] != "one.example" || got["api_key"] != "" || got["api_secret"] != "" {
		t.Fatal("metadata read included credentials")
	}
	info := store.Connections()
	encoded, err := json.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	if len(info) != 3 || info[1].LogicalSite != "trusted" || strings.Contains(string(encoded), "one-secret") || strings.Contains(string(encoded), "one.example") {
		t.Fatal("incorrect connection discovery")
	}
}

func TestDefaultLogicalSiteRequiresStoredTarget(t *testing.T) {
	store, path := newTestStore(t)
	c := Connection{Provider: "omada", Profile: "default"}
	for _, tc := range []struct{ name, host, overrideHost, overrideSite, want string }{
		{"same target", "controller.example", "", "", "trusted"},
		{"different host", "controller.example", "other.example", "", ""},
		{"different vendor site", "controller.example", "", "management", ""},
		{"no bound host", "", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := store.Set(c.Provider, c.Profile, Entry{"host": tc.host, "site": "trusted", "logical_site": "trusted"}); err != nil {
				t.Fatal(err)
			}
			env := func(key string) string {
				if key == "OMADA_HOST" {
					return tc.overrideHost
				}
				return ""
			}
			got := Resolve(c, Entry{"site": tc.overrideSite}, env, path, false)
			if got["logical_site"] != tc.want {
				t.Fatal("connection grouping crossed its stored binding")
			}
		})
	}
}

func TestCredentialSchemaRegistration(t *testing.T) {
	t.Cleanup(ClearRegisteredFields)
	if err := RegisterFields("sensor", []Field{
		{Name: "host", Env: "SENSOR_HOST", Required: true},
		{Name: "token", Env: "SENSOR_TOKEN", Required: true, Secret: true},
	}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		fields []Field
	}{
		{"omada", nil},
		{"sensor", nil},
		{"omada-client", []Field{{Name: "token", Env: "OMADA_CLIENT_SECRET"}}},
		{"sensor-extra", []Field{{Name: "left", Env: "SENSOR_EXTRA_KEY"}, {Name: "right", Env: "SENSOR_EXTRA_KEY"}}},
		{"invalid", []Field{{Name: "profile"}}},
		{"invalid", []Field{{Name: "host", Secret: true}}},
		{"invalid", []Field{{Name: "token", Env: "OMADA_CLIENT_SECRET"}}},
		{"invalid", []Field{{Name: "token"}, {Name: "token"}}},
	} {
		if RegisterFields(tc.name, tc.fields) == nil {
			t.Fatal("invalid declaration accepted")
		}
	}
	copy := FieldsFor("sensor")
	copy[1].Secret = false
	if !SecretField("sensor", "token") {
		t.Fatal("returned fields alias registered schema")
	}
}

func TestConnectionDiagnosticRedaction(t *testing.T) {
	c := Connection{Provider: "opnsense"}
	values := Entry{"host": "firewall.example", "api_key": "fixture", "api_secret": "fixture-long"}
	if c.Require(values) != nil || c.RedactError(nil, values) != nil {
		t.Fatal("valid credentials were rejected")
	}
	if err := c.Require(Entry{"api_key": "fixture"}); err == nil || strings.Contains(err.Error(), "fixture") {
		t.Fatal("missing credentials must expose field names only")
	}
	original := errors.New("timeout")
	if c.RedactError(original, values) != original {
		t.Fatal("unchanged error lost its identity")
	}
	got := c.RedactError(errors.New("fixture-long rejected fixture"), values)
	if got.Error() != "[redacted] rejected [redacted]" {
		t.Fatal("overlapping credential values were disclosed")
	}
}

func TestLegacyConnectionStoreAndMissingPaths(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("USERPROFILE", tmp)
	c := Connection{Provider: "legacy"}
	if err := c.Require(nil); err == nil {
		t.Fatal("missing legacy host")
	}
	if got := Resolve(c, nil, nil, "", true); got["host"] != "" {
		t.Fatal("unconfigured connection resolved a host")
	}
	store, err := Open(DefaultPath())
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Set("probe", "management", Entry{"host": "probe.example"}); err != nil {
		t.Fatal(err)
	}
	if err = store.Set(c.Provider, c.ProfileName(), Entry{"host": "controller.example", "client_secret": "fixture-secret"}); err != nil {
		t.Fatal(err)
	}
	if len(store.Connections()) != 1 {
		t.Fatal("SSH probe appeared as a controller connection")
	}
	values := Resolve(c, nil, nil, "", true)
	if c.Require(values) != nil || values["client_secret"] != "fixture-secret" {
		t.Fatal("legacy stored entry did not resolve")
	}
	if got := Resolve(c, nil, nil, "", false); len(got) != 0 {
		t.Fatal("unqualified metadata read consulted store")
	}
	if err = os.WriteFile(DefaultPath(), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := Resolve(c, nil, nil, "", true); len(got) != 0 {
		t.Fatal("damaged store returned credentials")
	}
}

func TestDefaultControllerEnvironmentAndStore(t *testing.T) {
	store, path := newTestStore(t)
	for _, tc := range []struct{ provider, key, secret, env string }{{"omada", "client_id", "client_secret", "OMADA_CLIENT_ID"}, {"opnsense", "api_key", "api_secret", "OPNSENSE_API_KEY"}} {
		c := Connection{Provider: tc.provider}
		if err := store.Set(c.Provider, c.ProfileName(), Entry{"host": "controller.example", tc.key: "stored-key", tc.secret: "stored-secret"}); err != nil {
			t.Fatal(err)
		}
		env := func(name string) string {
			if name == tc.env {
				return "from-env"
			}
			return ""
		}
		got := Resolve(c, nil, env, path, true)
		if got[tc.key] != "from-env" || got[tc.secret] != "stored-secret" || got["host"] != "controller.example" {
			t.Fatal("default environment and encrypted store precedence changed")
		}
	}
}
