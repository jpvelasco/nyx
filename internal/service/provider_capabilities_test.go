package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/credentials"
	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/testutil/providerfixture"
)

type permissionStatus int

func (permissionStatus) Error() string     { return "synthetic request failed" }
func (s permissionStatus) HTTPStatus() int { return int(s) }

func TestCapabilityReport(t *testing.T) {
	providerfixture.IsolateProviders(t)
	adapter := new(providerfixture.ReadOnlyAdapter)
	if err := providers.Register(adapter); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "credentials.json")
	getenv := func(name string) string {
		if name == "SYNTHETIC_HOST" {
			return "edge.example"
		}
		return ""
	}
	report := func(opts CapabilityOptions) ProviderCapabilities {
		t.Helper()
		rows, err := ProviderCapabilityReport(t.Context(), opts, path, getenv)
		if err != nil || len(rows) != 1 {
			t.Fatalf("capability report: rows=%v error=%v", rows, err)
		}
		return rows[0]
	}
	first := report(CapabilityOptions{})
	if len(first.Connections) != 1 || first.Connections[0].InfoAccess != "unverified" || first.Connections[0].Profile != "default" {
		t.Fatal(first)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("offline report created a store: %v", err)
	}
	store, err := credentials.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set(adapter.Name(), "routing", credentials.Entry{"host": "firewall.example", "api_key": "fixture-secret", "logical_site": "management"}); err != nil {
		t.Fatal(err)
	}
	aliases := report(CapabilityOptions{})
	if len(aliases.Connections) != 2 || aliases.Connections[1].LogicalSite != "management" || adapter.Calls != 0 {
		t.Fatal(aliases, adapter.Calls)
	}
	live := report(CapabilityOptions{Observe: true, Provider: adapter.Name()})
	if live.Connections[0].InfoAccess != "missing_credentials" || live.Connections[1].InfoAccess != "observed" || adapter.Calls != 1 {
		t.Fatal(live, adapter.Calls)
	}
	for _, tc := range []struct {
		err  error
		want string
	}{{permissionStatus(http.StatusForbidden), "permission_denied"}, {permissionStatus(http.StatusUnauthorized), "authentication_failed"}, {permissionStatus(http.StatusNotFound), "unsupported"}, {errors.New("fixture-secret"), "unavailable"}} {
		adapter.Err = tc.err
		row := report(CapabilityOptions{Observe: true, Profile: "routing"})
		encoded, err := json.Marshal(row)
		if err != nil || len(row.Connections) != 1 || row.Connections[0].InfoAccess != tc.want || strings.Contains(string(encoded), "fixture-secret") || strings.Contains(string(encoded), "firewall.example") {
			t.Fatal(row, err)
		}
	}
	if _, err := ProviderCapabilityReport(t.Context(), CapabilityOptions{Provider: "absent"}, path, getenv); err == nil {
		t.Fatal("accepted unknown provider")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := ProviderCapabilityReport(ctx, CapabilityOptions{Observe: true}, path, getenv); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
