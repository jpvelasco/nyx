package seendb

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Entry struct {
	SeenAt  time.Time `json:"seen_at"`
	Virtual bool      `json:"virtual"`
}

type SeenDB struct {
	mu              sync.Mutex
	VirtualNetworks map[string]Entry `json:"virtual_networks"`
	path            string
}

// New returns an empty in-memory SeenDB with no backing file.
// Acks are accepted but not persisted.
func New() *SeenDB {
	return &SeenDB{VirtualNetworks: map[string]Entry{}}
}

// Load reads from ~/.nyx/seen.json. On any error it returns a valid in-memory
// DB with no path so that callers never receive a nil pointer; acks will be
// lost across runs but no audit command will panic or fail.
func Load() *SeenDB {
	home, err := os.UserHomeDir()
	if err != nil {
		return &SeenDB{VirtualNetworks: map[string]Entry{}}
	}
	db, err := LoadFrom(filepath.Join(home, ".nyx", "seen.json"))
	if err != nil {
		return &SeenDB{VirtualNetworks: map[string]Entry{}}
	}
	return db
}

func LoadFrom(path string) (*SeenDB, error) {
	db := &SeenDB{VirtualNetworks: map[string]Entry{}, path: path}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return db, nil
	}
	if err != nil {
		return db, err
	}
	if err := json.Unmarshal(data, db); err != nil {
		return db, err
	}
	db.path = path
	return db, nil
}

func (db *SeenDB) IsVirtualAcked(cidr string) bool {
	db.mu.Lock()
	defer db.mu.Unlock()
	_, ok := db.VirtualNetworks[cidr]
	return ok
}

func (db *SeenDB) GetEntry(cidr string) *Entry {
	db.mu.Lock()
	defer db.mu.Unlock()
	e, ok := db.VirtualNetworks[cidr]
	if !ok {
		return nil
	}
	return &e
}

func (db *SeenDB) AckVirtual(cidr string) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	db.VirtualNetworks[cidr] = Entry{SeenAt: time.Now().UTC(), Virtual: true}
	return db.save()
}

// save must be called with mu held.
func (db *SeenDB) save() error {
	if db.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(db.path), 0750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(db.path, data, 0640)
}
