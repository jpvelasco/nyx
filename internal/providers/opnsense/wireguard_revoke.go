package opnsense

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
)

var peerUUID = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// ValidPeerUUID accepts a single canonical row identifier.
func ValidPeerUUID(id string) bool { return peerUUID.MatchString(id) }

// RevokeWireGuardPeer disables or removes exactly one configured peer. Explicit disable is idempotent.
func (c *Client) RevokeWireGuardPeer(ctx context.Context, uuid string, remove bool) error {
	if !ValidPeerUUID(uuid) {
		return errors.New("invalid peer UUID")
	}
	path := "/wireguard/client/toggle_client/" + uuid + "/0"
	want := "disabled"
	if remove {
		path = "/wireguard/client/del_client/" + uuid
		want = "deleted"
	}
	return c.wireGuardAction(ctx, path, want)
}

// ReloadWireGuard activates a staged change. A positive response is required.
func (c *Client) ReloadWireGuard(ctx context.Context) error {
	return c.wireGuardAction(ctx, "/wireguard/service/reconfigure", "ok")
}

func (c *Client) wireGuardAction(ctx context.Context, path, want string) error {
	resp, err := c.doWithReplay(ctx, http.MethodPost, path, []byte(`{}`), false)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var result struct {
		Result string `json:"result"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return errors.New("invalid WireGuard response")
	}
	if !strings.EqualFold(result.Result, want) {
		return errors.New("WireGuard did not confirm the operation")
	}
	return nil
}
