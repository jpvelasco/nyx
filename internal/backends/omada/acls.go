package omada

import (
	"context"
	"encoding/json"
	"fmt"
)

// ACLRule represents a firewall / inter-VLAN ACL rule in Omada.
type ACLRule struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Status     bool   `json:"status"`
	Policy     string `json:"policy"`   // "accept" | "drop"
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
// returns whichever responds with data.
func (c *Client) GetACLRules(ctx context.Context, siteID string) ([]ACLRule, error) {
	paths := []string{
		fmt.Sprintf("sites/%s/setting/firewall/acl?currentPage=1&currentPageSize=200", siteID),
		fmt.Sprintf("sites/%s/setting/firewall/acls?currentPage=1&currentPageSize=200", siteID),
		fmt.Sprintf("sites/%s/acl?currentPage=1&currentPageSize=200", siteID),
		fmt.Sprintf("sites/%s/setting/acl?currentPage=1&currentPageSize=200", siteID),
	}
	return c.tryACLPaths(ctx, paths)
}

// GetGatewayACLRules tries known gateway ACL paths.
func (c *Client) GetGatewayACLRules(ctx context.Context, siteID string) ([]ACLRule, error) {
	paths := []string{
		fmt.Sprintf("sites/%s/setting/firewall/gwacl?currentPage=1&currentPageSize=200", siteID),
		fmt.Sprintf("sites/%s/setting/firewall/gwacls?currentPage=1&currentPageSize=200", siteID),
		fmt.Sprintf("sites/%s/setting/gateway/acl?currentPage=1&currentPageSize=200", siteID),
	}
	return c.tryACLPaths(ctx, paths)
}

func (c *Client) tryACLPaths(ctx context.Context, paths []string) ([]ACLRule, error) {
	for _, path := range paths {
		var raw json.RawMessage
		if err := c.get(ctx, path, &raw); err != nil {
			continue
		}
		var paged struct {
			TotalRows int       `json:"totalRows"`
			Data      []ACLRule `json:"data"`
		}
		if err := json.Unmarshal(raw, &paged); err == nil {
			// Return even if empty — a valid empty response means no rules configured
			if paged.TotalRows >= 0 {
				return paged.Data, nil
			}
		}
		var direct []ACLRule
		if err := json.Unmarshal(raw, &direct); err == nil {
			return direct, nil
		}
	}
	return nil, fmt.Errorf("no ACL endpoint responded with parseable data")
}
