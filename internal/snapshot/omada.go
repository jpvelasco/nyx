package snapshot

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"github.com/jpvelasco/nyx/internal/backends/omada"
	"github.com/jpvelasco/nyx/internal/filewrite"
)

type omadaSiteBaseline struct {
	Hash      string           `json:"hash"`
	Resources omada.SiteConfig `json:"resources"`
}

// OmadaSiteChange identifies one changed object by its private snapshot key.
type OmadaSiteChange struct {
	Kind      string `json:"kind"`
	Reference string `json:"reference"`
	Status    string `json:"status"`
}

func omadaSiteBaselinePath(scope [sha256.Size]byte) (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "omada-site-config", hex.EncodeToString(scope[:])+".json"), nil
}

func hashOmadaResources(resources omada.SiteConfig) (string, error) {
	data, err := json.Marshal(resources)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(data)), nil
}

// SaveOmadaSiteConfig atomically replaces the baseline for the selected site.
func SaveOmadaSiteConfig(state omada.SiteConfigState) error {
	path, err := omadaSiteBaselinePath(state.Scope)
	if err != nil {
		return err
	}
	hash, err := hashOmadaResources(state.Resources)
	if err != nil {
		return fmt.Errorf("hashing site configuration: %w", err)
	}
	data, err := json.Marshal(omadaSiteBaseline{Hash: hash, Resources: state.Resources})
	if err != nil {
		return fmt.Errorf("serializing site configuration: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil { // nosemgrep: private directory requires execute for traversal
		return fmt.Errorf("creating site configuration directory: %w", err)
	}
	return filewrite.Write(path, bytes.NewReader(data))
}

// CompareOmadaSiteConfig compares live state with the saved baseline without
// exposing the underlying configuration or modifying the snapshot.
func CompareOmadaSiteConfig(state omada.SiteConfigState) ([]OmadaSiteChange, error) {
	path, err := omadaSiteBaselinePath(state.Scope)
	if err != nil {
		return nil, err
	}
	// #nosec G304 — path is generated from the site fingerprint in the snapshot directory.
	data, err := os.ReadFile(path) // nosemgrep
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("no baseline for this site; run 'nyx omada site-config snapshot' first")
	}
	if err != nil {
		return nil, fmt.Errorf("reading site configuration baseline: %w", err)
	}
	var baseline omadaSiteBaseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return nil, fmt.Errorf("invalid site configuration baseline")
	}
	hash, err := hashOmadaResources(baseline.Resources)
	if err != nil || hash != baseline.Hash {
		return nil, fmt.Errorf("site configuration baseline hash mismatch")
	}
	return diffOmadaSiteConfig(baseline.Resources, state.Resources), nil
}

func diffOmadaSiteConfig(before, after omada.SiteConfig) []OmadaSiteChange {
	changes := make([]OmadaSiteChange, 0)
	for _, kind := range slices.Sorted(maps.Keys(before)) {
		for _, ref := range slices.Sorted(maps.Keys(before[kind])) {
			switch current, exists := after[kind][ref]; {
			case !exists:
				changes = append(changes, OmadaSiteChange{Kind: kind, Reference: ref, Status: "removed"})
			case !bytes.Equal(before[kind][ref], current):
				changes = append(changes, OmadaSiteChange{Kind: kind, Reference: ref, Status: "modified"})
			}
		}
	}
	for _, kind := range slices.Sorted(maps.Keys(after)) {
		for _, ref := range slices.Sorted(maps.Keys(after[kind])) {
			if _, exists := before[kind][ref]; !exists {
				changes = append(changes, OmadaSiteChange{Kind: kind, Reference: ref, Status: "added"})
			}
		}
	}
	return changes
}
