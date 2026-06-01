package seendb

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type Entry struct {
	SeenAt  time.Time `json:"seen_at"`
	Virtual bool      `json:"virtual"`
}

type SeenDB struct {
	VirtualNetworks map[string]Entry `json:"virtual_networks"`
	path            string
}

func Load() (*SeenDB, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return empty("")
	}
	return LoadFrom(filepath.Join(home, ".nyx", "seen.json"))
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

func empty(path string) (*SeenDB, error) {
	return &SeenDB{VirtualNetworks: map[string]Entry{}, path: path}, nil
}

func (db *SeenDB) IsVirtualAcked(cidr string) bool {
	_, ok := db.VirtualNetworks[cidr]
	return ok
}

func (db *SeenDB) GetEntry(cidr string) *Entry {
	e, ok := db.VirtualNetworks[cidr]
	if !ok {
		return nil
	}
	return &e
}

func (db *SeenDB) AckVirtual(cidr string) error {
	db.VirtualNetworks[cidr] = Entry{SeenAt: time.Now().UTC(), Virtual: true}
	return db.save()
}

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
