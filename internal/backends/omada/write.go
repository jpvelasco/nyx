package omada

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// aclRuleWrite is the writable subset of an ACL rule. The rule id and index
// are controller-managed and must not be sent in write payloads.
type aclRuleWrite struct {
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
}

func ruleToWrite(rule ACLRule) aclRuleWrite {
	return aclRuleWrite{
		Name:       rule.Name,
		Status:     rule.Status,
		Policy:     rule.Policy,
		Protocols:  rule.Protocols,
		SourceType: rule.SourceType,
		SourceID:   rule.SourceID,
		SourceName: rule.SourceName,
		DestType:   rule.DestType,
		DestID:     rule.DestID,
		DestName:   rule.DestName,
	}
}

// CreateACLRule creates a switch ACL rule on the site and returns the
// controller's view of the created rule.
func (c *Client) CreateACLRule(ctx context.Context, siteID string, rule ACLRule) (*ACLRule, error) {
	path := fmt.Sprintf("sites/%s/setting/firewall/acl", siteID)
	var created ACLRule
	if err := c.post(ctx, path, ruleToWrite(rule), &created); err != nil {
		return nil, fmt.Errorf("creating ACL rule: %w", err)
	}
	return &created, nil
}

// UpdateACLRule replaces the writable fields of an existing rule. The Omada
// API expects the full rule payload on update, so the caller must pass the
// current rule with the desired fields changed.
func (c *Client) UpdateACLRule(ctx context.Context, siteID, ruleID string, rule ACLRule) (*ACLRule, error) {
	path := fmt.Sprintf("sites/%s/setting/firewall/acl/%s", siteID, ruleID)
	var updated ACLRule
	if err := c.patch(ctx, path, ruleToWrite(rule), &updated); err != nil {
		return nil, fmt.Errorf("updating ACL rule %q: %w", ruleID, err)
	}
	return &updated, nil
}

// patch performs an authenticated PATCH with a JSON body and decodes the
// result field into dest. dest may be nil.
func (c *Client) patch(ctx context.Context, path string, body interface{}, dest interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshaling request body: %w", err)
	}
	return c.doRequest(ctx, http.MethodPatch, path, data, dest)
}
