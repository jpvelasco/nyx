package omada

import (
	"context"
	"fmt"
)

// ACLRule represents a firewall / inter-VLAN ACL rule in Omada.
type ACLRule struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Status     bool   `json:"status"`   // enabled/disabled
	Policy     string `json:"policy"`   // "accept" | "drop"
	Protocols  string `json:"protocols"` // "all" | "tcp" | "udp" | etc.
	SourceType string `json:"srcType"`  // "network" | "ipgroup" | "ip"
	SourceID   string `json:"srcId"`
	SourceName string `json:"srcName"`
	DestType   string `json:"dstType"`
	DestID     string `json:"dstId"`
	DestName   string `json:"dstName"`
	Index      int    `json:"index"`
}

// GetACLRules returns inter-VLAN firewall ACL rules for the given site.
func (c *Client) GetACLRules(ctx context.Context, siteID string) ([]ACLRule, error) {
	var result struct {
		TotalRows int       `json:"totalRows"`
		Data      []ACLRule `json:"data"`
	}
	path := fmt.Sprintf("sites/%s/setting/firewall/acls?currentPage=1&currentPageSize=200", siteID)
	if err := c.get(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("getting ACL rules for site %s: %w", siteID, err)
	}
	return result.Data, nil
}

// GetGatewayACLRules returns gateway-level ACL rules (WAN/inter-zone rules).
// These live under a different endpoint on controller 6.x.
func (c *Client) GetGatewayACLRules(ctx context.Context, siteID string) ([]ACLRule, error) {
	var result struct {
		TotalRows int       `json:"totalRows"`
		Data      []ACLRule `json:"data"`
	}
	path := fmt.Sprintf("sites/%s/setting/firewall/gwacls?currentPage=1&currentPageSize=200", siteID)
	if err := c.get(ctx, path, &result); err != nil {
		return nil, fmt.Errorf("getting gateway ACL rules for site %s: %w", siteID, err)
	}
	return result.Data, nil
}
