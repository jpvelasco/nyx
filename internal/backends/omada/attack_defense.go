package omada

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
)

// AttackDefenseSettings contains selected site configuration flags.
type AttackDefenseSettings struct {
	TCPScanEnabled      *bool `json:"tcpScanEnable,omitempty"`
	TCPScanReject       *bool `json:"tcpScanReject,omitempty"`
	LargePingEnabled    *bool `json:"largePingEnable,omitempty"`
	ICMPTimestampReject *bool `json:"icmpTimestampRequestReject,omitempty"`
}

func (c *Client) GetAttackDefenseSettings(ctx context.Context, siteID string) (AttackDefenseSettings, error) {
	var settings AttackDefenseSettings
	err := c.get(ctx, "sites/"+url.PathEscape(siteID)+"/attack-defense", &settings)
	return settings, attackDefenseError("reading attack-defense settings", err)
}

// ClientBlockStatus reads the controller's administrative client block flag.
func (c *Client) ClientBlockStatus(ctx context.Context, siteID, mac string) (*bool, error) {
	path, err := attackDefenseClientPath(siteID, mac)
	if err != nil {
		return nil, err
	}
	var detail struct {
		Blocked *bool `json:"blocked"`
	}
	err = c.get(ctx, path, &detail)
	return detail.Blocked, attackDefenseError("reading client block status", err)
}

// UnblockClient removes the administrative client block from a single client.
func (c *Client) UnblockClient(ctx context.Context, siteID, mac string) error {
	path, err := attackDefenseClientPath(siteID, mac)
	if err != nil {
		return err
	}
	return attackDefenseError("unblocking controller client; on failure verify current status before retrying", c.postCreate(ctx, path+"/unblock", nil, nil))
}

func attackDefenseClientPath(siteID, mac string) (string, error) {
	addr, err := net.ParseMAC(mac)
	if err != nil || len(addr) != 6 {
		return "", errors.New("client MAC must be a 48-bit MAC address")
	}
	return "sites/" + url.PathEscape(siteID) + "/clients/" + dashMAC(addr.String()), nil
}

func attackDefenseError(operation string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s: %w", operation, err)
	}
	var api *apiError
	if errors.As(err, &api) {
		if api.ErrorCode != 0 {
			return fmt.Errorf("%s: controller error %d", operation, api.ErrorCode)
		}
		if api.StatusCode != 0 {
			return fmt.Errorf("%s: HTTP %d", operation, api.StatusCode)
		}
	}
	return fmt.Errorf("%s: controller transport or protocol error", operation)
}
