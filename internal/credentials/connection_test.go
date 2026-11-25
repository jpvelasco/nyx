package credentials

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestNamedConnectionIsolation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for profile, entry := range map[string]Entry{"default": {"host": "default.example", "api_key": "default-key", "api_secret": "default-secret"}, "one": {"host": "one.example", "api_key": "one-key", "api_secret": "one-secret", "logical_site": "trusted"}, "two": {"host": "two.example", "api_key": "two-key"}} {
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
	if err := RegisterFields("sensor", []Field{{Name: "host", Env: "SENSOR_HOST", Required: true}, {Name: "token", Env: "SENSOR_TOKEN", Required: true, Secret: true}}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		fields []Field
	}{
		{"omada", nil}, {"sensor", nil}, {"invalid", []Field{{Name: "profile"}}}, {"invalid", []Field{{Name: "host", Secret: true}}}, {"invalid", []Field{{Name: "token", Env: "OMADA_CLIENT_SECRET"}}}, {"invalid", []Field{{Name: "token"}, {Name: "token"}}},
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
