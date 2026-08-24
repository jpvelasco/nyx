package omada

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// aclRuleWrite is the Open API writable payload. Rule id and index are
// controller-managed and must not be sent; the rule type comes from the
// per-scope path, not the body. Names are resolved client-side and are not
// accepted on write.
type aclRuleWrite struct {
	Name        string       `json:"description"`
	Status      bool         `json:"status"`
	Policy      ACLPolicy    `json:"policy"`
	Protocols   []int        `json:"protocols"`
	SourceType  EndpointKind `json:"sourceType"`
	SourceIDs   []string     `json:"sourceIds"`
	DestType    EndpointKind `json:"destinationType"`
	DestIDs     []string     `json:"destinationIds"`
	Direction   ACLDirection `json:"direction,omitempty"`
	TimeRangeID string       `json:"timeRangeId,omitempty"`
	// BindingType is required on switch-scope rules: 0 = all ports,
	// 1 = the customAclPorts list. Nil (omitted) for gateway scope.
	BindingType *int `json:"bindingType,omitempty"`
	// EtherType and BiDirectional are constant for nyx-managed rules.
	EtherType     aclEtherType `json:"etherType"`
	BiDirectional bool         `json:"biDirectional"`
	// Gateway-scope fields. syslog/stateMode/states are required by the
	// controller on osg-acls writes; the controller rejects their
	// omission with errorCode -1001.
	Syslog    bool       `json:"syslog,omitempty"`
	StateMode *int       `json:"stateMode,omitempty"` // gateway-only; explicit 0 must survive encoding
	States    *aclStates `json:"states,omitempty"`
}

type aclEtherType struct {
	Enable bool `json:"enable"`
}

// aclStates is the gateway rule's connection-state set. All four states are
// enabled by default.
type aclStates struct {
	StateNew    bool `json:"stateNew"`
	Established bool `json:"established"`
	Related     bool `json:"related"`
	Invalid     bool `json:"invalid"`
}

// gatewayStateMode is the required stateMode for osg-acls writes (stateful
// inspection). Package-level so its address can be sent as an explicit 0.
var gatewayStateMode = 0

func ruleToWrite(rule ACLRule) aclRuleWrite {
	protocols := rule.Protocols
	if len(protocols) == 0 {
		protocols = []int{ProtocolAll}
	}
	w := aclRuleWrite{
		Name:        rule.Name,
		Status:      rule.Status,
		Policy:      rule.Policy,
		Protocols:   protocols,
		SourceType:  rule.SourceType,
		SourceIDs:   rule.SourceIDs,
		DestType:    rule.DestType,
		DestIDs:     rule.DestIDs,
		Direction:   rule.Direction,
		TimeRangeID: rule.TimeRangeID,
		EtherType:   aclEtherType{Enable: false},
	}
	switch rule.Type {
	case ACLTypeSwitch:
		// Switch-scope rules require the bindingType field (0 = all
		// ports, 1 = custom ports); gateway-scope rules do not carry
		// it. Fresh rules default to 0; updates preserve the read value.
		w.BindingType = &rule.BindingType
	case ACLTypeGateway:
		// Gateway-scope writes require state tracking fields; the
		// controller rejects creates that omit them (-1001).
		w.Syslog = true
		w.StateMode = &gatewayStateMode
		w.States = &aclStates{StateNew: true, Established: true, Related: true, Invalid: true}
	}
	return w
}

// CreateACLRule POSTs a rule to its per-scope collection. The create
// response carries no rule id — the caller refetches the list to find the
// new rule.
func (c *Client) CreateACLRule(ctx context.Context, siteID string, rule ACLRule) error {
	if err := c.post(ctx, aclScopePath(siteID, rule.Type), ruleToWrite(rule), nil); err != nil {
		return fmt.Errorf("creating ACL rule: %w", err)
	}
	return nil
}

// UpdateACLRule PUTs the full writable payload of an existing rule to its
// per-scope item path.
func (c *Client) UpdateACLRule(ctx context.Context, siteID, ruleID string, rule ACLRule) error {
	if err := c.put(ctx, fmt.Sprintf("%s/%s", aclScopePath(siteID, rule.Type), ruleID), ruleToWrite(rule), nil); err != nil {
		return fmt.Errorf("updating ACL rule %q: %w", ruleID, err)
	}
	return nil
}

// DeleteACLRule removes a rule by id via the scope-agnostic item path.
func (c *Client) DeleteACLRule(ctx context.Context, siteID, ruleID string) error {
	if err := c.delete(ctx, aclDeletePath(siteID, ruleID)); err != nil {
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
