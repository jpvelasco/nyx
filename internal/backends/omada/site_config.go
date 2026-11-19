package omada

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// SiteConfig contains the full Open API objects indexed by resource kind and
// a site-specific reference. Its values are for local snapshot storage only.
type SiteConfig map[string]map[string]json.RawMessage

// SiteConfigState identifies one controller/site and its observed resources.
type SiteConfigState struct {
	Scope     [sha256.Size]byte
	Resources SiteConfig
}

type siteConfigRow map[string]any

func (r *siteConfigRow) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	return decoder.Decode((*map[string]any)(r))
}

// GetSiteConfig reads the same site-scoped inventory collections as the
// typed network, switch ACL, and WLAN methods, retaining every wire field.
func (c *Client) GetSiteConfig(ctx context.Context, siteID string) (SiteConfigState, error) {
	state := SiteConfigState{
		Scope:     sha256.Sum256([]byte(c.omadaCID + "\x00" + siteID)),
		Resources: make(SiteConfig),
	}
	collections := []struct{ kind, path string }{
		{"network", lanNetworksPath(siteID)},
		{"switch-acl", aclScopePath(siteID, ACLTypeSwitch)},
		{"wlan-group", wlanGroupsPath(siteID)},
		{"ssid", ssidsPath(siteID)},
	}
	for _, collection := range collections {
		rows, _, err := fetchPaged[siteConfigRow](ctx, c, collection.path, defaultPageSize)
		if err != nil {
			return SiteConfigState{}, fmt.Errorf("reading %s configuration: %w", collection.kind, err)
		}
		resources, err := indexSiteConfigRows(state.Scope, collection.kind, rows)
		if err != nil {
			return SiteConfigState{}, fmt.Errorf("indexing %s configuration: %w", collection.kind, err)
		}
		state.Resources[collection.kind] = resources
	}
	return state, nil
}

func indexSiteConfigRows(scope [sha256.Size]byte, kind string, rows []siteConfigRow) (map[string]json.RawMessage, error) {
	resources := make(map[string]json.RawMessage, len(rows))
	for _, row := range rows {
		id, _ := row["id"].(string)
		if id == "" {
			return nil, fmt.Errorf("resource is missing its id")
		}
		// Including the scope and kind keeps equal IDs in distinct collections separate.
		digest := sha256.Sum256([]byte(string(scope[:]) + "\x00" + kind + "\x00" + id))
		ref := hex.EncodeToString(digest[:])
		if _, exists := resources[ref]; exists {
			return nil, fmt.Errorf("duplicate resource id")
		}
		data, err := json.Marshal(row)
		if err != nil {
			return nil, err
		}
		resources[ref] = data
	}
	return resources, nil
}
