package omada

import (
	"context"
	"fmt"
)

// ACLRule represents a firewall / inter-VLAN ACL rule in Omada.
type ACLRule struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Status     bool   `json:"status"`
	Policy     string `json:"policy"` // "accept" | "drop"
	Protocols  string `json:"protocols"`
	SourceType string `json:"srcType"`
	SourceID   string `json:"srcId"`
	SourceName string `json:"srcName"`
	DestType   string `json:"dstType"`
	DestID     string `json:"dstId"`
	DestName   string `json:"dstName"`
	Index      int    `json:"index"`
}

// GetACLRules tries all known ACL endpoint paths for controller 6.x and
// returns whichever responds with data, walking every page.
func (c *Client) GetACLRules(ctx context.Context, siteID string) ([]ACLRule, error) {
	paths := []string{
		fmt.Sprintf("sites/%s/setting/firewall/acl", siteID),
		fmt.Sprintf("sites/%s/setting/firewall/acls", siteID),
		fmt.Sprintf("sites/%s/acl", siteID),
		fmt.Sprintf("sites/%s/setting/acl", siteID),
	}
	return c.tryACLPaths(ctx, paths)
}

// GetGatewayACLRules tries known gateway ACL paths, walking every page.
func (c *Client) GetGatewayACLRules(ctx context.Context, siteID string) ([]ACLRule, error) {
	paths := []string{
		fmt.Sprintf("sites/%s/setting/firewall/gwacl", siteID),
		fmt.Sprintf("sites/%s/setting/firewall/gwacls", siteID),
		fmt.Sprintf("sites/%s/setting/gateway/acl", siteID),
	}
	return c.tryACLPaths(ctx, paths)
}

func (c *Client) tryACLPaths(ctx context.Context, paths []string) ([]ACLRule, error) {
	for _, path := range paths {
		rules, _, err := fetchPaged[ACLRule](ctx, c, path, defaultPageSize)
		if err != nil {
			continue
		}
		// Return even if empty — a valid empty response means no rules configured
		return rules, nil
	}
	return nil, fmt.Errorf("no ACL endpoint responded with parseable data")
}
