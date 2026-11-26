package opnsense

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
)

// SelectedPeer contains the public fields needed for exact peer and server readback.
type SelectedPeer struct {
	Name, PublicKey   string
	Enabled           bool
	Networks, Servers []string
}

func (c *Client) SelectedPeer(ctx context.Context, uuid string) (SelectedPeer, error) {
	var out SelectedPeer
	if !ValidPeerUUID(uuid) {
		return out, errors.New("invalid peer UUID")
	}
	raw, err := getRaw(ctx, c, "/wireguard/client/get_client/"+uuid)
	if err != nil {
		return out, err
	}
	var data struct {
		Client struct {
			Name      string          `json:"name"`
			PublicKey string          `json:"pubkey"`
			Enabled   string          `json:"enabled"`
			Networks  json.RawMessage `json:"tunneladdress"`
			Servers   json.RawMessage `json:"servers"`
		} `json:"client"`
	}
	if json.Unmarshal(raw, &data) != nil {
		return out, errors.New("invalid selected peer record")
	}
	rec := data.Client
	if rec.Name == "" || rec.PublicKey == "" || (rec.Enabled != "0" && rec.Enabled != "1") || len(rec.Servers) == 0 || len(rec.Networks) == 0 {
		return out, errors.New("incomplete selected peer record")
	}
	out = SelectedPeer{Name: rec.Name, PublicKey: rec.PublicKey, Enabled: rec.Enabled == "1", Networks: decodeStringList(rec.Networks), Servers: decodeStringList(rec.Servers)}
	if len(out.Networks) == 0 {
		return out, errors.New("cannot verify existing peer networks")
	}
	for _, id := range out.Servers {
		if !ValidPeerUUID(id) {
			return out, errors.New("invalid existing server association")
		}
	}
	slices.Sort(out.Servers)
	return out, nil
}

// SaveSelectedPeer sends only the operator-approved public fields. Existing key material and unrelated fields stay with the appliance.
func (c *Client) SaveSelectedPeer(ctx context.Context, uuid string, peer SelectedPeer) (string, error) {
	path := "/wireguard/client/add_client"
	if uuid != "" {
		if !ValidPeerUUID(uuid) {
			return "", errors.New("invalid peer UUID")
		}
		path = "/wireguard/client/set_client/" + uuid
	}
	enabled := "0"
	if peer.Enabled {
		enabled = "1"
	}
	body, err := json.Marshal(map[string]any{"client": map[string]string{"name": peer.Name, "pubkey": peer.PublicKey, "tunneladdress": strings.Join(peer.Networks, ","), "servers": strings.Join(peer.Servers, ","), "enabled": enabled}})
	if err != nil {
		return "", err
	}
	resp, err := c.doWithReplay(ctx, http.MethodPost, path, body, false)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var result struct{ Result, UUID string }
	if json.NewDecoder(resp.Body).Decode(&result) != nil || result.Result != "saved" {
		return "", errors.New("peer save unconfirmed")
	}
	if uuid != "" {
		return uuid, nil
	}
	if !ValidPeerUUID(result.UUID) {
		return "", errors.New("peer creation unconfirmed")
	}
	return result.UUID, nil
}
