package snapshot

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/jpvelasco/nyx/internal/backends/omada"
)

func TestOmadaSiteConfigRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	scope := sha256.Sum256([]byte("synthetic-site"))
	before := omada.SiteConfigState{Scope: scope, Resources: omada.SiteConfig{
		"network": {"modified-ref": json.RawMessage(`{"vlan":10}`), "removed-ref": json.RawMessage(`{"vlan":20}`)},
	}}
	if _, err := CompareOmadaSiteConfig(before); err == nil {
		t.Fatal("expected missing baseline")
	}
	if err := SaveOmadaSiteConfig(before); err != nil {
		t.Fatal(err)
	}
	path, err := omadaSiteBaselinePath(scope)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(path) != filepath.Join(home, ".nyx", "snapshots", "omada-site-config") {
		t.Fatal("wrong baseline directory")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("permissions = %o, want 600", info.Mode().Perm())
	}
	if snapshots, err := ListSnapshots(); err != nil || len(snapshots) != 0 {
		t.Fatalf("audit snapshots = %v, error = %v", snapshots, err)
	}
	if changes, err := CompareOmadaSiteConfig(before); err != nil || changes == nil || len(changes) != 0 {
		t.Fatalf("identical snapshot changes = %v, error = %v", changes, err)
	}
	after := omada.SiteConfigState{Scope: scope, Resources: omada.SiteConfig{
		"network": {"modified-ref": json.RawMessage(`{"vlan":30}`)},
		"ssid":    {"added-ref": json.RawMessage(`{"name":"example"}`)},
	}}
	changes, err := CompareOmadaSiteConfig(after)
	want := []OmadaSiteChange{
		{Kind: "network", Reference: "modified-ref", Status: "modified"},
		{Kind: "network", Reference: "removed-ref", Status: "removed"},
		{Kind: "ssid", Reference: "added-ref", Status: "added"},
	}
	if err != nil || !reflect.DeepEqual(changes, want) {
		t.Fatalf("changes = %v, error = %v", changes, err)
	}
	otherSite := after
	otherSite.Scope = sha256.Sum256([]byte("other-synthetic-site"))
	if _, err := CompareOmadaSiteConfig(otherSite); err == nil {
		t.Fatal("site unexpectedly reused another site's baseline")
	}
	if err := SaveOmadaSiteConfig(after); err != nil {
		t.Fatal(err)
	}
	if changes, err := CompareOmadaSiteConfig(after); err != nil || len(changes) != 0 {
		t.Fatalf("resaved baseline changes = %v, error = %v", changes, err)
	}
	if err := os.WriteFile(path, []byte(`{"hash":"invalid","resources":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := CompareOmadaSiteConfig(after); err == nil {
		t.Fatal("accepted a baseline with the wrong hash")
	}
}

func TestOmadaSiteConfigRejectsInvalidStorage(t *testing.T) {
	setHome := func(t *testing.T, home string) {
		t.Helper()
		t.Setenv("HOME", home)
		t.Setenv("USERPROFILE", home)
	}
	state := omada.SiteConfigState{Scope: sha256.Sum256([]byte("synthetic-site")), Resources: omada.SiteConfig{"network": {"ref": json.RawMessage(`{}`)}}}
	t.Run("home unavailable", func(t *testing.T) {
		setHome(t, "")
		if err := SaveOmadaSiteConfig(state); err == nil {
			t.Error("saved with no home directory")
		}
		if _, err := CompareOmadaSiteConfig(state); err == nil {
			t.Error("compared with no home directory")
		}
	})
	t.Run("invalid resource encoding", func(t *testing.T) {
		setHome(t, t.TempDir())
		bad := state
		bad.Resources = omada.SiteConfig{"network": {"ref": json.RawMessage(`{`)}}
		if err := SaveOmadaSiteConfig(bad); err == nil {
			t.Fatal("saved malformed resource JSON")
		}
	})
	t.Run("invalid baseline path", func(t *testing.T) {
		setHome(t, t.TempDir())
		path, err := omadaSiteBaselinePath(state.Scope)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(filepath.Dir(path)), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Dir(path), nil, 0600); err != nil {
			t.Fatal(err)
		}
		if err := SaveOmadaSiteConfig(state); err == nil {
			t.Fatal("saved with a file blocking the baseline directory")
		}
		if _, err := CompareOmadaSiteConfig(state); err == nil {
			t.Fatal("compared with a file blocking the baseline directory")
		}
	})
	t.Run("malformed baseline", func(t *testing.T) {
		setHome(t, t.TempDir())
		if err := SaveOmadaSiteConfig(state); err != nil {
			t.Fatal(err)
		}
		path, err := omadaSiteBaselinePath(state.Scope)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(`{`), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := CompareOmadaSiteConfig(state); err == nil {
			t.Fatal("accepted malformed baseline JSON")
		}
	})
}
