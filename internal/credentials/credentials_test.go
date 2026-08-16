package credentials

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func newTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credentials.json")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	return s, path
}

func TestSetGetRoundtrip(t *testing.T) {
	s, _ := newTestStore(t)
	if err := s.Set("omada", "default", Entry{
		"host":     "192.168.1.1",
		"username": "admin",
		"password": "hunter2",
		"site":     "Site1",
	}); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	entry, ok := s.Get("omada", "default")
	if !ok {
		t.Fatalf("Get = ok=%v, want ok=true", ok)
	}
	if entry["password"] != "hunter2" || entry["host"] != "192.168.1.1" {
		t.Errorf("Get returned unexpected entry: %v", entry)
	}

	// Mutating the returned entry must not corrupt the store.
	entry["password"] = "tampered"
	stored, _ := s.Get("omada", "default")
	if stored["password"] != "hunter2" {
		t.Error("mutating a returned entry changed the store")
	}
}

func TestOverlayFillsEmptyKeysOnly(t *testing.T) {
	s, path := newTestStore(t)
	if err := s.Set("omada", "default", Entry{
		"host":     "192.168.1.1",
		"username": "admin",
		"password": "secret",
		"site":     "Home",
	}); err != nil {
		t.Fatalf("Set: %v", err)
	}

	dest := Fields{Host: "flag-host"}
	Overlay(path, "omada", "default", &dest)
	if dest.Host != "flag-host" {
		t.Errorf("host = %q, want flag value preserved", dest.Host)
	}
	if dest.Username != "admin" || dest.Password != "secret" || dest.Site != "Home" {
		t.Errorf("dest = %+v, want store fill for empty keys", dest)
	}

	Overlay(path, "omada", "missing", &dest)
	if dest.Username != "admin" {
		t.Error("missing entry must not clear dest")
	}

	Overlay(filepath.Join(t.TempDir(), "nope.json"), "omada", "default", &dest)
	Overlay("", "omada", "default", nil)
}

func TestGetMissing(t *testing.T) {
	s, _ := newTestStore(t)
	if _, ok := s.Get("omada", "default"); ok {
		t.Error("Get on empty store = ok=true, want ok=false")
	}
	s.Set("omada", "default", Entry{"host": "h"})
	if _, ok := s.Get("omada", "other"); ok {
		t.Error("Get with unknown name = ok=true, want ok=false")
	}
}

func TestRemoveMissingNameWithExistingProvider(t *testing.T) {
	s, _ := newTestStore(t)
	s.Set("omada", "default", Entry{"host": "h"})
	if err := s.Remove("omada", "missing"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Remove unknown name err = %v, want ErrNotFound", err)
	}
}

func TestDefaultPath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("no home dir: %v", err)
	}
	want := filepath.Join(home, ".nyx", "credentials.json")
	if got := DefaultPath(); got != want {
		t.Errorf("DefaultPath() = %q, want %q", got, want)
	}
}

func TestListAndProviders(t *testing.T) {
	s, _ := newTestStore(t)
	s.Set("omada", "default", Entry{"host": "h"})
	s.Set("omada", "backup", Entry{"host": "b"})
	s.Set("probe", "home", Entry{"host": "p"})

	names := s.List("omada")
	if strings.Join(names, ",") != "backup,default" {
		t.Errorf("List(omada) = %v, want [backup default]", names)
	}
	if got := strings.Join(s.Providers(), ","); got != "omada,probe" {
		t.Errorf("Providers() = %v, want [omada probe]", got)
	}
}

func TestRemove(t *testing.T) {
	s, _ := newTestStore(t)
	s.Set("omada", "default", Entry{"host": "h"})

	if err := s.Remove("omada", "default"); err != nil {
		t.Fatalf("Remove failed: %v", err)
	}
	if _, ok := s.Get("omada", "default"); ok {
		t.Error("entry still present after Remove")
	}
	if err := s.Remove("omada", "default"); !errors.Is(err, ErrNotFound) {
		t.Errorf("second Remove err = %v, want ErrNotFound", err)
	}
}

func TestValidation(t *testing.T) {
	s, _ := newTestStore(t)
	if err := s.Set("", "default", Entry{"host": "h"}); err == nil {
		t.Error("Set with empty provider should fail")
	}
	if err := s.Set("omada", "", Entry{"host": "h"}); err == nil {
		t.Error("Set with empty name should fail")
	}
	if err := s.Set("omada", "default", Entry{}); err == nil {
		t.Error("Set with empty entry should fail")
	}
}

func TestEncryptedAtRest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	secret := "sup3r-secret-value"
	if err := s.Set("omada", "default", Entry{"password": secret}); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	raw, err := os.ReadFile(path) // nosemgrep: go_filesystem_rule-fileread
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if strings.Contains(string(raw), secret) {
		t.Error("store file contains plaintext secret")
	}
	if strings.Contains(string(raw), "omada") {
		t.Error("store file contains plaintext provider name")
	}
	if strings.Contains(string(raw), "password") {
		t.Error("store file contains plaintext field name")
	}
}

func TestReloadPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if err := s.Set("opnsense", "fw1", Entry{"api_key": "k", "api_secret": "s"}); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	entry, ok := reopened.Get("opnsense", "fw1")
	if !ok || entry["api_secret"] != "s" {
		t.Errorf("reopened Get = ok=%v entry=%v", ok, entry)
	}
}

func TestCorruptStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	if _, err := Open(path); err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if err := os.WriteFile(path, []byte("garbage-not-encrypted"), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if _, err := Open(path); err == nil {
		t.Error("Open on corrupt store should fail")
	}

	// Ciphertext shorter than the GCM nonce must fail cleanly too.
	if err := os.WriteFile(path, []byte("tiny"), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if _, err := Open(path); err == nil {
		t.Error("Open on truncated store should fail")
	}
}

func TestKeyFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions are not enforced on Windows")
	}
	_, path := newTestStore(t)
	info, err := os.Stat(path + ".key")
	if err != nil {
		t.Fatalf("key file missing: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("key file perm = %o, want 600", perm)
	}
}

func TestCorruptKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	if _, err := Open(path); err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	// A wrong-length key must be rejected, not silently regenerated.
	if err := os.WriteFile(path+".key", []byte("tooshort"), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if _, err := Open(path); err == nil {
		t.Error("Open with an invalid key file should fail")
	}
}

func TestOpenKeyWriteError(t *testing.T) {
	// Parent is a file, so neither the key nor the store can be written.
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if _, err := Open(filepath.Join(blocker, "credentials.json")); err == nil {
		t.Error("Open under a file-as-directory should fail")
	}
}

func TestSaveWriteError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	if err := s.Set("omada", "default", Entry{"host": "h"}); err != nil {
		t.Fatalf("Set failed: %v", err)
	}
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatalf("Chmod failed: %v", err)
	}
	defer os.Chmod(path, 0600)
	if err := s.Set("omada", "default", Entry{"host": "h2"}); err == nil {
		t.Error("Set against a read-only store should fail")
	}
}

func TestLoadUnmarshalError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	if _, err := Open(path); err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	// Codacy false positive: path is generated by t.TempDir(), not from user input.
	key, err := os.ReadFile(path + ".key") // nosemgrep: go_filesystem_rule-fileread
	if err != nil {
		t.Fatalf("ReadFile key failed: %v", err)
	}
	// Valid AEAD ciphertext over non-JSON plaintext: decryption succeeds,
	// decoding must fail loudly instead of silently resetting the store.
	sealed, err := encrypt([]byte("not-json{"), key)
	if err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}
	if err := os.WriteFile(path, sealed, 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}
	if _, err := Open(path); err == nil {
		t.Error("Open with undecodable plaintext should fail")
	}
}
