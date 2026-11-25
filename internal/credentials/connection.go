package credentials

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/jpvelasco/nyx/internal/credentials/credmanager"
)

// Connection identifies one credential record. An empty profile selects default.
type Connection struct {
	Provider string `json:"provider"`
	Profile  string `json:"profile"`
}

// ConnectionInfo contains only operator-assigned names, never a host or key.
type ConnectionInfo struct {
	Connection
	LogicalSite string `json:"logical_site,omitempty"`
	Site        string `json:"site,omitempty"`
}

// Field describes a registered input. Values are held separately in Entry.
type Field struct {
	Name        string `json:"name"`
	Env         string `json:"env,omitempty"`
	Required    bool   `json:"required,omitempty"`
	Secret      bool   `json:"secret,omitempty"`
	Description string `json:"description,omitempty"`
}

var builtinFields = map[string][]Field{
	"omada": {
		{Name: "host", Env: "OMADA_HOST", Required: true},
		{Name: "client_id", Env: "OMADA_CLIENT_ID", Required: true, Description: "Omada Open API client ID"},
		{Name: "client_secret", Env: "OMADA_CLIENT_SECRET", Required: true, Secret: true, Description: "Omada Open API client secret"},
		{Name: "site", Env: "OMADA_SITE"},
	},
	"opnsense": {
		{Name: "host", Env: "OPNSENSE_HOST", Required: true},
		{Name: "api_key", Env: "OPNSENSE_API_KEY", Required: true, Secret: true, Description: "OPNsense API key"},
		{Name: "api_secret", Env: "OPNSENSE_API_SECRET", Required: true, Secret: true, Description: "OPNsense API secret"},
	},
	"probe": {{Name: "host", Required: true}, {Name: "username", Required: true}, {Name: "key", Required: true}},
}

var (
	schemaMu     sync.RWMutex
	customFields = map[string][]Field{}
	fieldName    = regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
)

// RegisterFields registers a new adapter's credential shape during registration.
func RegisterFields(provider string, fields []Field) error {
	schemaMu.Lock()
	defer schemaMu.Unlock()
	_, exists := customFields[provider]
	if builtinFields[provider] != nil || exists {
		return fmt.Errorf("credential schema already registered for %q", provider)
	}
	seen := map[string]bool{"profile": true, "logical_site": true, "skip_tls_verify": true, "ca_cert": true, "ca_cert_path": true, "spec": true, "out": true, "debug": true, "include_acl_names": true, "include_firewall_details": true, "help": true}
	for _, f := range fields {
		if !fieldName.MatchString(f.Name) || seen[f.Name] || (f.Secret && (f.Name == "host" || f.Name == "site")) {
			return fmt.Errorf("invalid or duplicate credential field for %q", provider)
		}
		if f.Env != "" && !strings.HasPrefix(f.Env, strings.ToUpper(strings.ReplaceAll(provider, "-", "_"))+"_") {
			return fmt.Errorf("credential environment variable outside provider namespace for %q", provider)
		}
		seen[f.Name] = true
	}
	customFields[provider] = slices.Clone(fields)
	return nil
}

// ClearRegisteredFields clears runtime credential declarations in provider registry tests.
func ClearRegisteredFields() {
	schemaMu.Lock()
	defer schemaMu.Unlock()
	clear(customFields)
}

// FieldsFor returns public metadata without credential values.
func FieldsFor(provider string) []Field {
	schemaMu.RLock()
	defer schemaMu.RUnlock()
	if fields, ok := customFields[provider]; ok {
		return slices.Clone(fields)
	}
	return slices.Clone(builtinFields[provider])
}

// ProfileName returns the profile used as the encrypted-store key.
func (c Connection) ProfileName() string {
	if c.Profile == "" {
		return "default"
	}
	return c.Profile
}

func connectionFields(provider string) []Field {
	fields := FieldsFor(provider)
	if fields == nil {
		// Legacy adapters can read their own existing store records. These
		// fields intentionally have no ambient environment or keyring source.
		fields = []Field{{Name: "host", Required: true}, {Name: "site"}, {Name: "client_id"}, {Name: "client_secret", Secret: true}}
	}
	return fields
}

// Resolve selects the connection before consulting fallback credentials. Ambient
// environment variables and legacy host-keyed Windows entries belong to default.
func Resolve(c Connection, supplied Entry, getenv func(string) string, path string, authenticated bool) Entry {
	fields := connectionFields(c.Provider)
	profile := c.ProfileName()
	def := profile == "default"
	if getenv == nil {
		getenv = os.Getenv
	}
	out := Entry{}
	for _, field := range fields {
		if !authenticated && field.Name != "host" && field.Name != "site" {
			continue
		}
		v := supplied[field.Name]
		if v == "" && def && field.Env != "" {
			v = getenv(field.Env)
		}
		if v != "" {
			out[field.Name] = v
		}
	}
	if c.Profile == "" && !authenticated {
		return out
	}
	if authenticated && def {
		switch c.Provider {
		case "omada":
			out["client_id"], out["client_secret"] = credmanager.OverlayOmada(out["host"], out["client_id"], out["client_secret"])
		case "opnsense":
			out["api_key"], out["api_secret"] = credmanager.OverlayOpnsense(out["host"], out["api_key"], out["api_secret"])
		}
	}
	if path == "" {
		path = DefaultPath()
	}
	if _, err := os.Stat(path); err != nil {
		return out
	}
	store, err := Open(path)
	if err != nil {
		return out
	}
	stored, _ := store.Get(c.Provider, profile)
	retargeted := differentTarget(out, stored, "host") || differentTarget(out, stored, "site")
	if !def && retargeted {
		return out
	}
	for _, field := range fields {
		if (authenticated || field.Name == "host" || field.Name == "site") && out[field.Name] == "" && stored[field.Name] != "" {
			out[field.Name] = stored[field.Name]
		}
	}
	if !retargeted && stored["host"] != "" && stored["logical_site"] != "" {
		out["logical_site"] = stored["logical_site"]
	}
	return out
}

func differentTarget(explicit, stored Entry, key string) bool {
	return explicit[key] != "" && explicit[key] != stored[key]
}

// Connections lists configured provider records and their site identities in stable order.
func (s *Store) Connections() []ConnectionInfo {
	result := []ConnectionInfo{}
	for _, provider := range s.Providers() {
		if provider == "probe" {
			continue
		}
		for _, name := range s.List(provider) {
			e, _ := s.Get(provider, name)
			info := ConnectionInfo{Connection: Connection{Provider: provider, Profile: name}, Site: e["site"]}
			if e["host"] != "" {
				info.LogicalSite = e["logical_site"]
			}
			result = append(result, info)
		}
	}
	return result
}

// SecretField identifies values that must never be echoed or included in diagnostics.
func SecretField(provider, name string) bool {
	for _, f := range FieldsFor(provider) {
		if f.Name == name {
			return f.Secret
		}
	}
	return false
}

// Require reports missing field names without including values or calling a controller.
func (c Connection) Require(e Entry) error {
	missing := MissingRequired(c.Provider, e)
	if FieldsFor(c.Provider) == nil && e["host"] == "" {
		missing = []string{"host"}
	}
	if len(missing) > 0 {
		return fmt.Errorf("provider %s profile %s is missing required fields: %s", c.Provider, c.ProfileName(), strings.Join(missing, ", "))
	}
	return nil
}

// RedactError strips any declared secret echoed by an adapter from its diagnostic.
func (c Connection) RedactError(err error, e Entry) error {
	if err == nil {
		return nil
	}
	var secrets []string
	for _, field := range connectionFields(c.Provider) {
		if field.Secret && e[field.Name] != "" {
			secrets = append(secrets, e[field.Name])
		}
	}
	// Replace longer secrets first when one value is a prefix of another.
	slices.SortFunc(secrets, func(a, b string) int { return len(b) - len(a) })
	message := err.Error()
	for _, value := range secrets {
		message = strings.ReplaceAll(message, value, "[redacted]")
	}
	if message == err.Error() {
		return err
	}
	return errors.New(message)
}
