package omada

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// aclRuleWrite is the 6.x writable payload. Rule id and index are
// controller-managed and must not be sent. Names are resolved client-side
// and are not accepted on write.
type aclRuleWrite struct {
	Name        string       `json:"name"`
	Type        ACLType      `json:"type"`
	Status      bool         `json:"status"`
	Policy      ACLPolicy    `json:"policy"`
	Protocols   []int        `json:"protocols"`
	SourceType  EndpointKind `json:"sourceType"`
	SourceIDs   []string     `json:"sourceIds"`
	DestType    EndpointKind `json:"destinationType"`
	DestIDs     []string     `json:"destinationIds"`
	Direction   ACLDirection `json:"direction,omitempty"`
	TimeRangeID string       `json:"timeRangeId,omitempty"`
}

func ruleToWrite(rule ACLRule) aclRuleWrite {
	protocols := rule.Protocols
	if len(protocols) == 0 {
		protocols = []int{ProtocolAll}
	}
	return aclRuleWrite{
		Name:        rule.Name,
		Type:        rule.Type,
		Status:      rule.Status,
		Policy:      rule.Policy,
		Protocols:   protocols,
		SourceType:  rule.SourceType,
		SourceIDs:   rule.SourceIDs,
		DestType:    rule.DestType,
		DestIDs:     rule.DestIDs,
		Direction:   rule.Direction,
		TimeRangeID: rule.TimeRangeID,
	}
}

// CreateACLRule POSTs a rule to the unified ACL collection.
func (c *Client) CreateACLRule(ctx context.Context, siteID string, rule ACLRule) (*ACLRule, error) {
	var created ACLRule
	if err := c.post(ctx, aclCollectionPath(siteID), ruleToWrite(rule), &created); err != nil {
		return nil, fmt.Errorf("creating ACL rule: %w", err)
	}
	return &created, nil
}

// UpdateACLRule PUTs the full writable payload of an existing rule.
func (c *Client) UpdateACLRule(ctx context.Context, siteID, ruleID string, rule ACLRule) (*ACLRule, error) {
	var updated ACLRule
	if err := c.put(ctx, aclItemPath(siteID, ruleID), ruleToWrite(rule), &updated); err != nil {
		return nil, fmt.Errorf("updating ACL rule %q: %w", ruleID, err)
	}
	return &updated, nil
}

// DeleteACLRule removes a rule by id.
func (c *Client) DeleteACLRule(ctx context.Context, siteID, ruleID string) error {
	if err := c.delete(ctx, aclItemPath(siteID, ruleID)); err != nil {
		return fmt.Errorf("deleting ACL rule %q: %w", ruleID, err)
	}
	return nil
}

// put performs an authenticated PUT with a JSON body and decodes the
// result field into dest. dest may be nil.
func (c *Client) put(ctx context.Context, path string, body interface{}, dest interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("marshaling request body: %w", err)
	}
	return c.doRequest(ctx, http.MethodPut, path, data, dest)
}

// delete performs an authenticated DELETE with no body.
func (c *Client) delete(ctx context.Context, path string) error {
	return c.doRequest(ctx, http.MethodDelete, path, nil, nil)
}
