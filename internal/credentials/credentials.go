// Package credentials implements a minimal credential store under ~/.nyx.
// Interactive TTY prompts live on `nyx credentials set`; live
// per-provider verification is `nyx credentials verify --live`; MCP
// credentials_status reports store completeness and env-var presence
// without values. OS keyring support exists on Windows for Omada and
// OPNsense: credmanager reads the Windows Credential Manager entry
// nyx-omada-<host> or nyx-opnsense-<host> between the env-var and
// store layers (see docs/bdd/mcp-credentials.md). Omada Open API
// client-credentials cover the OAuth surface — there is no separate
// OAuth flow.
//
// Security posture: entries are encrypted with AES-256-GCM before being
// written to disk, but the key is stored beside the ciphertext
// (<path>.key). This protects against casual exposure (plaintext grep,
// accidental dump, sync to a partially-readable backup) — NOT against a
// local attacker who can read the key file, and it does not protect
// backups that include the key. The OS keyring (see credmanager) is the
// hardening path; treat the current store as obfuscated-at-rest.
//
// Storage layout:
//   - <path>               — AES-256-GCM encrypted JSON envelope
//   - <path>.key           — 32-byte random key, 0600, created on first use
//   - <path>.lock          — advisory lock file serializing read-modify-write
//     transactions across handles and processes
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
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Entry is a single credential record: a set of string fields whose keys
// are provider-defined (e.g. host, client_id, client_secret for omada).
type Entry map[string]string

// Requirements lists the fields each known provider must carry in an
// entry. Unknown providers have no required fields.
var Requirements = map[string][]string{
	"omada":    {"host", "client_id", "client_secret"},
	"opnsense": {"host", "api_key", "api_secret"},
	"probe":    {"host", "username", "key"},
}

// OptionalFields are prompted when `nyx credentials set` runs with no
// --set flags on a TTY. They are never required for verify / status.
var OptionalFields = map[string][]string{
	"omada": {"site"},
}

// secretFields are never echoed on a TTY prompt and never printed.
var secretFields = map[string]bool{
	"client_secret": true,
	"api_secret":    true,
}

// IsSecret reports whether field is a secret (no-echo prompt).
func IsSecret(field string) bool {
	return secretFields[field]
}

// MissingRequired returns the required fields that are empty on entry.
// Unknown providers return nil.
func MissingRequired(provider string, entry Entry) []string {
	var missing []string
	for _, field := range Requirements[provider] {
		if strings.TrimSpace(entry[field]) == "" {
			missing = append(missing, field)
		}
	}
	return missing
}

// EntryStatus is a value-free completeness report for one stored entry.
type EntryStatus struct {
	Provider      string   `json:"provider"`
	Name          string   `json:"name"`
	Complete      bool     `json:"complete"`
	MissingFields []string `json:"missing_fields,omitempty"`
}

// Status reports completeness for every stored entry. It never includes
// field values.
func (s *Store) Status() []EntryStatus {
	var out []EntryStatus
	for _, provider := range s.Providers() {
		for _, name := range s.List(provider) {
			entry, _ := s.Get(provider, name)
			missing := MissingRequired(provider, entry)
			st := EntryStatus{
				Provider: provider,
				Name:     name,
				Complete: len(missing) == 0,
			}
			if len(missing) > 0 {
				st.MissingFields = missing
			}
			out = append(out, st)
		}
	}
	if out == nil {
		return []EntryStatus{}
	}
	return out
}

// Store is an encrypted-at-rest credential store rooted at a single file.
type Store struct {
	path string
	key  []byte
	data map[string]map[string]Entry // provider → name → entry

	// mu guards the in-memory data map within this handle. The sibling
	// lock file serializes read-modify-write transactions across handles
	// and processes.
	mu sync.Mutex
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
//
// The store directory is created when missing so a custom store path can
// initialize cleanly, and the sibling lock file serializes first-use key
// creation against concurrent processes.
func Open(path string) (*Store, error) {
	s := &Store{path: path, data: map[string]map[string]Entry{}}
	//nolint:gosec
	if err := os.MkdirAll(filepath.Dir(filepath.Clean(path)), 0700); err != nil { // nosemgrep — 0700 is the least-privilege permission for a directory
		return nil, fmt.Errorf("creating credential directory: %w", err)
	}
	lock, err := acquireFileLock(s.lockPath())
	if err != nil {
		return nil, fmt.Errorf("locking credential store: %w", err)
	}
	defer lock.release()
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
	return s.mutate(func(data map[string]map[string]Entry) error {
		if data[provider] == nil {
			data[provider] = map[string]Entry{}
		}
		data[provider][name] = entry
		return nil
	})
}

// Fields is the typed overlay target for provider credentials. A struct
// (not a map) keeps host/site distinct from the credential values so a
// printed hostname cannot be treated as a leaked secret.
type Fields struct {
	Host         string
	ClientID     string
	ClientSecret string
	Site         string
	// APIKey / APISecret carry the OPNsense credential pair (store keys
	// api_key / api_secret under provider "opnsense").
	APIKey    string
	APISecret string
}

// Overlay fills empty Fields from the named store entry. Store failures
// and missing entries are ignored — dest is left as-is for those keys so
// callers can keep env vars / flags as the primary source.
func Overlay(path, provider, name string, dest *Fields) {
	if dest == nil {
		return
	}
	if path == "" {
		path = DefaultPath()
	}
	store, err := Open(path)
	if err != nil {
		return
	}
	entry, ok := store.Get(provider, name)
	if !ok {
		return
	}
	if dest.Host == "" {
		dest.Host = entry["host"]
	}
	if dest.ClientID == "" {
		dest.ClientID = entry["client_id"]
	}
	if dest.ClientSecret == "" {
		dest.ClientSecret = entry["client_secret"]
	}
	if dest.Site == "" {
		dest.Site = entry["site"]
	}
	if dest.APIKey == "" {
		dest.APIKey = entry["api_key"]
	}
	if dest.APISecret == "" {
		dest.APISecret = entry["api_secret"]
	}
}

// Get returns the stored entry. ok is false when the entry does not exist.
func (s *Store) Get(provider, name string) (Entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
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
	s.mu.Lock()
	defer s.mu.Unlock()
	names := make([]string, 0, len(s.data[provider]))
	for name := range s.data[provider] {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// Remove deletes an entry. Returns ErrNotFound when it does not exist.
func (s *Store) Remove(provider, name string) error {
	return s.mutate(func(data map[string]map[string]Entry) error {
		providerEntries, ok := data[provider]
		if !ok {
			return ErrNotFound
		}
		if _, ok := providerEntries[name]; !ok {
			return ErrNotFound
		}
		delete(providerEntries, name)
		if len(providerEntries) == 0 {
			delete(data, provider)
		}
		return nil
	})
}

// mutate runs a read-modify-write transaction against the store file: it
// takes the sibling lock file, reloads the latest content so concurrent
// handles and processes merge instead of overwriting each other, applies
// fn, and atomically replaces the file. The lock also keeps first-use key
// creation races from producing divergent keys.
func (s *Store) mutate(fn func(data map[string]map[string]Entry) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	lock, err := acquireFileLock(s.lockPath())
	if err != nil {
		return fmt.Errorf("locking credential store: %w", err)
	}
	defer lock.release()

	data, err := readStore(s.path, s.key)
	if err != nil {
		return err
	}
	if err := fn(data); err != nil {
		return err
	}
	if err := writeStore(s.path, data, s.key); err != nil {
		return err
	}
	s.data = data
	return nil
}

// Providers returns the sorted set of providers that have at least one entry.
func (s *Store) Providers() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	providers := make([]string, 0, len(s.data))
	for p := range s.data {
		providers = append(providers, p)
	}
	sort.Strings(providers)
	return providers
}

// loadKey reads the 32-byte AES key, generating and persisting it on first
// use. Only a genuinely missing key file starts first-use creation; every
// other read failure is propagated so an unreadable key (an escaping
// symlink, a permission problem) can never be treated as first use and
// overwritten, which would destroy the existing ciphertext.
func (s *Store) loadKey() error {
	keyPath := s.keyPath()
	data, err := s.readKey()
	switch {
	case err == nil:
		if len(data) != 32 {
			return fmt.Errorf("credential key %s has invalid length %d", keyPath, len(data))
		}
		s.key = data
		return nil
	case errors.Is(err, fs.ErrNotExist):
		key := make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return fmt.Errorf("generating credential key: %w", err)
		}
		if err := writeKeyFile(keyPath, key); err != nil {
			return err
		}
		s.key = key
		return nil
	default:
		return fmt.Errorf("reading credential key: %w", err)
	}
}

// writeKeyFile creates the key file exclusively with owner-only
// permissions. An unexpected existing path — including a symlink — is an
// error, never a file to rewrite.
func writeKeyFile(keyPath string, key []byte) error {
	f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600) // nosemgrep — keyPath is derived from the configured store path, same trust level as every other store sibling
	if err != nil {
		return fmt.Errorf("creating credential key: %w", err)
	}
	if _, err := f.Write(key); err != nil {
		f.Close()
		os.Remove(keyPath)
		return fmt.Errorf("writing credential key: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(keyPath)
		return fmt.Errorf("writing credential key: %w", err)
	}
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

// lockPath returns the advisory lock file beside the configured store file.
// It serializes read-modify-write transactions across handles and processes.
func (s *Store) lockPath() string {
	cleanPath := filepath.Clean(s.path)
	return filepath.Join(filepath.Dir(cleanPath), filepath.Base(cleanPath)+".lock")
}

// load reads and decrypts the store file into the handle.
func (s *Store) load() error {
	data, err := readStore(s.path, s.key)
	if err != nil {
		return err
	}
	s.data = data
	return nil
}

// readStore decrypts and decodes the store file at path. A missing file
// means an empty store.
func readStore(path string, key []byte) (map[string]map[string]Entry, error) {
	data := map[string]map[string]Entry{}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return data, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading credential store: %w", err)
	}
	plain, err := decrypt(raw, key)
	if err != nil {
		return nil, fmt.Errorf("decrypting credential store (was it tampered with or re-created?): %w", err)
	}
	if err := json.Unmarshal(plain, &data); err != nil {
		return nil, fmt.Errorf("decoding credential store: %w", err)
	}
	if data == nil {
		data = map[string]map[string]Entry{}
	}
	return data, nil
}

// writeStore encrypts data and atomically replaces the store file so a
// crash or a concurrent reader never observes a partial store.
func writeStore(path string, data map[string]map[string]Entry, key []byte) error {
	plain, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("encoding credential store: %w", err)
	}
	sealed, err := encrypt(plain, key)
	if err != nil {
		return err
	}
	dir := filepath.Dir(filepath.Clean(path))
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-")
	if err != nil {
		return fmt.Errorf("writing credential store: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the file has been renamed
	if _, err := tmp.Write(sealed); err != nil {
		tmp.Close()
		return fmt.Errorf("writing credential store: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("writing credential store: %w", err)
	}
	if err := os.Chmod(tmpName, 0600); err != nil {
		return fmt.Errorf("writing credential store: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("replacing credential store: %w", err)
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
