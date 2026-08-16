// Package credentials implements a minimal credential store under ~/.nyx.
// Scoped MVP of the nyx credential vault: the OS keyring integration,
// interactive prompts, and per-provider live verification are tracked
// follow-ups.
//
// Security posture: entries are encrypted with AES-256-GCM before being
// written to disk, but the key is stored beside the ciphertext
// (<path>.key). This protects against casual exposure (plaintext grep,
// accidental dump, sync to a partially-readable backup) — NOT against a
// local attacker who can read the key file, and it does not protect
// backups that include the key. The OS keyring (tracked follow-up) is the
// hardening path; treat the current store as obfuscated-at-rest.
//
// Storage layout:
//   - <path>               — AES-256-GCM encrypted JSON envelope
//   - <path>.key           — 32-byte random key, 0600, created on first use
//
// Secrets are never logged, never written to spec files, and never
// returned by List (names only).
package credentials

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// Entry is a single credential record: a set of string fields whose keys
// are provider-defined (e.g. host, username, password for omada).
type Entry map[string]string

// Store is an encrypted-at-rest credential store rooted at a single file.
type Store struct {
	path string
	key  []byte
	data map[string]map[string]Entry // provider → name → entry
}

// ErrNotFound is returned when a provider/name combination has no entry.
var ErrNotFound = errors.New("credential entry not found")

// DefaultPath returns ~/.nyx/credentials.json.
func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "credentials.json"
	}
	return filepath.Join(home, ".nyx", "credentials.json")
}

// Open loads (or initializes) the store at path. The encryption key is
// read from a sibling <path>.key file, created on first use.
func Open(path string) (*Store, error) {
	s := &Store{path: path, data: map[string]map[string]Entry{}}
	if err := s.loadKey(); err != nil {
		return nil, err
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// Set stores an entry, creating it or replacing an existing one.
func (s *Store) Set(provider, name string, entry Entry) error {
	if provider == "" || name == "" {
		return errors.New("provider and name are required")
	}
	if len(entry) == 0 {
		return errors.New("entry must contain at least one field")
	}
	if s.data[provider] == nil {
		s.data[provider] = map[string]Entry{}
	}
	s.data[provider][name] = entry
	return s.save()
}

// Get returns the stored entry. ok is false when the entry does not exist.
func (s *Store) Get(provider, name string) (Entry, bool) {
	if s.data[provider] == nil {
		return nil, false
	}
	entry, ok := s.data[provider][name]
	if !ok {
		return nil, false
	}
	copyOf := make(Entry, len(entry))
	for k, v := range entry {
		copyOf[k] = v
	}
	return copyOf, true
}

// List returns the entry names for a provider, sorted. It never returns
// stored values.
func (s *Store) List(provider string) []string {
	names := make([]string, 0, len(s.data[provider]))
	for name := range s.data[provider] {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Remove deletes an entry. Returns ErrNotFound when it does not exist.
func (s *Store) Remove(provider, name string) error {
	if s.data[provider] == nil {
		return ErrNotFound
	}
	if _, ok := s.data[provider][name]; !ok {
		return ErrNotFound
	}
	delete(s.data[provider], name)
	if len(s.data[provider]) == 0 {
		delete(s.data, provider)
	}
	return s.save()
}

// Providers returns the sorted set of providers that have at least one entry.
func (s *Store) Providers() []string {
	providers := make([]string, 0, len(s.data))
	for p := range s.data {
		providers = append(providers, p)
	}
	sort.Strings(providers)
	return providers
}

// loadKey reads the 32-byte AES key, generating and persisting it on first use.
func (s *Store) loadKey() error {
	keyPath := s.keyPath()
	if data, err := s.readKey(); err == nil {
		if len(data) == 32 {
			s.key = data
			return nil
		}
		return fmt.Errorf("credential key %s has invalid length %d", keyPath, len(data))
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("generating credential key: %w", err)
	}
	//nolint:gosec
	if err := os.WriteFile(keyPath, key, 0600); err != nil { // nosemgrep
		return fmt.Errorf("writing credential key: %w", err)
	}
	s.key = key
	return nil
}

// readKey reads the sibling key through an os.Root anchored at the store's
// directory. This prevents path components in the configured store name from
// escaping that directory while preserving support for custom store paths.
func (s *Store) readKey() ([]byte, error) {
	cleanPath := filepath.Clean(s.path)
	root, err := os.OpenRoot(filepath.Dir(cleanPath))
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.ReadFile(filepath.Base(cleanPath) + ".key")
}

// keyPath returns the key file beside the configured store file. Constructing
// it from the cleaned directory and base name keeps the key as a sibling of
// the store without allowing path components from the store name to escape
// that directory.
func (s *Store) keyPath() string {
	cleanPath := filepath.Clean(s.path)
	return filepath.Join(filepath.Dir(cleanPath), filepath.Base(cleanPath)+".key")
}

// load reads and decrypts the store file. A missing file means an empty store.
func (s *Store) load() error {
	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading credential store: %w", err)
	}
	plain, err := decrypt(raw, s.key)
	if err != nil {
		return fmt.Errorf("decrypting credential store (was it tampered with or re-created?): %w", err)
	}
	if err := json.Unmarshal(plain, &s.data); err != nil {
		return fmt.Errorf("decoding credential store: %w", err)
	}
	return nil
}

// save encrypts and writes the store file with owner-only permissions.
func (s *Store) save() error {
	plain, err := json.Marshal(s.data)
	if err != nil {
		return fmt.Errorf("encoding credential store: %w", err)
	}
	sealed, err := encrypt(plain, s.key)
	if err != nil {
		return err
	}
	//nolint:gosec
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil { // nosemgrep
		return fmt.Errorf("creating credential directory: %w", err)
	}
	//nolint:gosec
	if err := os.WriteFile(s.path, sealed, 0600); err != nil { // nosemgrep
		return fmt.Errorf("writing credential store: %w", err)
	}
	return nil
}

// encrypt seals plaintext with AES-256-GCM: nonce (12 bytes) || ciphertext.
// The key length is validated by loadKey, so cipher construction cannot fail.
func encrypt(plain, key []byte) ([]byte, error) {
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generating nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plain, nil), nil
}

// decrypt reverses encrypt. The key length is validated by loadKey, so
// cipher construction cannot fail.
func decrypt(raw, key []byte) ([]byte, error) {
	block, _ := aes.NewCipher(key)
	gcm, _ := cipher.NewGCM(block)
	if len(raw) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
