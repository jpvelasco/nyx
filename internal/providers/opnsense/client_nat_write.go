package opnsense

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// natWriteEndpoints maps a NAT collection to its API paths.
type natWriteEndpoints struct {
	add    string
	setFmt string // format with %s for uuid
	delFmt string // format with %s for uuid
}

var (
	dNatEndpoints  = natWriteEndpoints{add: "/firewall/d_nat/add_rule", setFmt: "/firewall/d_nat/set_rule/%s", delFmt: "/firewall/d_nat/del_rule/%s"}
	oneToOneEndpts = natWriteEndpoints{add: "/firewall/one_to_one/add_rule", setFmt: "/firewall/one_to_one/set_rule/%s", delFmt: "/firewall/one_to_one/del_rule/%s"}
	sourceNatEndpt = natWriteEndpoints{add: "/firewall/source_nat/add_rule", setFmt: "/firewall/source_nat/set_rule/%s", delFmt: "/firewall/source_nat/del_rule/%s"}
)

// natRuleSpec is the agent-facing flat shape for a NAT rule write.
// One shared spec type; per-collection field sets are selected by
// natWirePayload.
type natRuleSpec struct {
	Sequence    string
	Interfaces  []string
	IPProtocol  string
	Protocol    string
	Source      string
	SourcePort  string
	Destination string
	Port        string
	LocalPort   string
	Target      string
	Mode        string
	Type        string
	Label       string
	Enabled     string // "0"/"1"; empty = use model default
}

// natWirePayload builds the JSON wire payload for a NAT rule write.
// The envelope is {"rule":{...}} (object) for all three collections.
// Per-collection field sets differ: d_nat uses nested source/destination
// with local-port and descr; one_to_one uses flat source_net/destination_net
// with external and type; source_nat uses flat source_net/destination_net
// with target/target_port.
func natWirePayload(coll string, spec natRuleSpec) ([]byte, error) {
	rule := map[string]interface{}{}
	switch coll {
	case "port_forward":
		// d_nat model (DNat.xml)
		if spec.Sequence != "" {
			rule["sequence"] = spec.Sequence
		}
		if len(spec.Interfaces) > 0 {
			rule["interface"] = strings.Join(spec.Interfaces, ",")
		}
		if spec.IPProtocol != "" {
			rule["ipprotocol"] = spec.IPProtocol
		}
		if spec.Protocol != "" {
			rule["protocol"] = strings.ToLower(spec.Protocol)
		}
		// Nested source/destination with network and port sub-fields.
		source := map[string]interface{}{}
		if spec.Source != "" {
			source["network"] = spec.Source
		}
		if spec.SourcePort != "" {
			source["port"] = spec.SourcePort
		}
		if len(source) > 0 {
			rule["source"] = source
		}
		dest := map[string]interface{}{}
		if spec.Destination != "" {
			dest["network"] = spec.Destination
		}
		if spec.Port != "" {
			dest["port"] = spec.Port
		}
		if len(dest) > 0 {
			rule["destination"] = dest
		}
		if spec.LocalPort != "" {
			rule["local-port"] = spec.LocalPort
		}
		if spec.Target != "" {
			rule["target"] = spec.Target
		}
		if spec.Label != "" {
			rule["descr"] = spec.Label
		}
	case "one_to_one":
		// Filter.xml onetoone.rule
		if spec.Enabled != "" {
			rule["enabled"] = spec.Enabled
		}
		if spec.Sequence != "" {
			rule["sequence"] = spec.Sequence
		}
		if len(spec.Interfaces) > 0 {
			rule["interface"] = strings.Join(spec.Interfaces, ",")
		}
		if spec.Type != "" {
			rule["type"] = spec.Type
		}
		if spec.Source != "" {
			rule["source_net"] = spec.Source
		}
		if spec.Destination != "" {
			rule["destination_net"] = spec.Destination
		}
		if spec.Target != "" {
			rule["external"] = spec.Target
		}
		if spec.Label != "" {
			rule["description"] = spec.Label
		}
	case "source_nat":
		// Filter.xml snatrules.rule
		if spec.Enabled != "" {
			rule["enabled"] = spec.Enabled
		}
		if spec.Sequence != "" {
			rule["sequence"] = spec.Sequence
		}
		if len(spec.Interfaces) > 0 {
			rule["interface"] = strings.Join(spec.Interfaces, ",")
		}
		if spec.IPProtocol != "" {
			rule["ipprotocol"] = spec.IPProtocol
		}
		if spec.Protocol != "" {
			rule["protocol"] = strings.ToLower(spec.Protocol)
		}
		if spec.Source != "" {
			rule["source_net"] = spec.Source
		}
		if spec.SourcePort != "" {
			rule["source_port"] = spec.SourcePort
		}
		if spec.Destination != "" {
			rule["destination_net"] = spec.Destination
		}
		if spec.Port != "" {
			rule["destination_port"] = spec.Port
		}
		if spec.Target != "" {
			rule["target"] = spec.Target
		}
		if spec.LocalPort != "" {
			rule["target_port"] = spec.LocalPort
		}
		if spec.Label != "" {
			rule["description"] = spec.Label
		}
	default:
		return nil, fmt.Errorf("unknown NAT collection %q", coll)
	}
	return json.Marshal(map[string]interface{}{"rule": rule})
}

// natWriteResult is the response shape for add_rule.
type natWriteResult struct {
	Result      string            `json:"result"`
	UUID        string            `json:"uuid"`
	Validations map[string]string `json:"validations"`
}

// natAddResult is the response for add_rule: {"result":"saved","uuid":"..."}
// or {"result":"failed","validations":{...}}.
func (c *Client) natAdd(ctx context.Context, path string, body []byte) (string, error) {
	resp, err := c.do(ctx, http.MethodPost, path, body)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var res natWriteResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", fmt.Errorf("decoding NAT write response: %w", err)
	}
	if res.Result != "saved" {
		if len(res.Validations) > 0 {
			return "", fmt.Errorf("NAT rule validation failed: %v", res.Validations)
		}
		return "", fmt.Errorf("NAT write returned %q", res.Result)
	}
	return res.UUID, nil
}

// natSetResult is the response for set_rule/del_rule/toggle_rule:
// {"result":"saved"} or {"result":"not found"} or {"result":"failed"}.
type natSetResult struct {
	Result string `json:"result"`
}

// natSet posts a set_rule or del_rule request.
func (c *Client) natSet(ctx context.Context, path string, body []byte) error {
	resp, err := c.do(ctx, http.MethodPost, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var res natSetResult
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return fmt.Errorf("decoding NAT set response: %w", err)
	}
	if res.Result == "failed" || res.Result == "not found" {
		return fmt.Errorf("NAT set returned %q", res.Result)
	}
	return nil
}

// S3.1 — Create port forward. POST /api/firewall/d_nat/add_rule with the
// {"rule":{...}} object envelope; success returns {"result":"saved","uuid":...}.
func (c *Client) CreatePortForwardRule(ctx context.Context, spec natRuleSpec) (string, error) {
	body, err := natWirePayload("port_forward", spec)
	if err != nil {
		return "", err
	}
	return c.natAdd(ctx, dNatEndpoints.add, body)
}

// S3.2 — Update port forward. POST /api/firewall/d_nat/set_rule/<uuid> with
// the full writable payload (the controller replaces the rule content).
func (c *Client) SetPortForwardRule(ctx context.Context, uuid string, spec natRuleSpec) error {
	body, err := natWirePayload("port_forward", spec)
	if err != nil {
		return err
	}
	return c.natSet(ctx, fmt.Sprintf(dNatEndpoints.setFmt, uuid), body)
}

// S3.3 — Delete port forward. POST /api/firewall/d_nat/del_rule/<uuid> with
// an empty JSON body; a missing uuid yields {"result":"not found"}.
func (c *Client) DeletePortForwardRule(ctx context.Context, uuid string) error {
	return c.natSet(ctx, fmt.Sprintf(dNatEndpoints.delFmt, uuid), []byte(`{}`))
}

// S3.4 — Enable/disable port forward. POST /api/firewall/d_nat/toggle_rule/<uuid>,<0|1>.
// The d_nat toggle uses the **disabled** polarity: disabled=true sends 1,
// disabled=false sends 0.
func (c *Client) TogglePortForwardRule(ctx context.Context, uuid string, disabled bool) error {
	flag := "0"
	if disabled {
		flag = "1"
	}
	return c.natSet(ctx, fmt.Sprintf("/firewall/d_nat/toggle_rule/%s,%s", uuid, flag), []byte(`{}`))
}

// S3.5 — Create one-to-one NAT. POST /api/firewall/one_to_one/add_rule.
func (c *Client) CreateOneToOneRule(ctx context.Context, spec natRuleSpec) (string, error) {
	body, err := natWirePayload("one_to_one", spec)
	if err != nil {
		return "", err
	}
	return c.natAdd(ctx, oneToOneEndpts.add, body)
}

// S3.5 — Update one-to-one NAT. POST /api/firewall/one_to_one/set_rule/<uuid>.
func (c *Client) SetOneToOneRule(ctx context.Context, uuid string, spec natRuleSpec) error {
	body, err := natWirePayload("one_to_one", spec)
	if err != nil {
		return err
	}
	return c.natSet(ctx, fmt.Sprintf(oneToOneEndpts.setFmt, uuid), body)
}

// S3.5 — Delete one-to-one NAT. POST /api/firewall/one_to_one/del_rule/<uuid>.
func (c *Client) DeleteOneToOneRule(ctx context.Context, uuid string) error {
	return c.natSet(ctx, fmt.Sprintf(oneToOneEndpts.delFmt, uuid), []byte(`{}`))
}

// S3.6 — Create source NAT. POST /api/firewall/source_nat/add_rule.
func (c *Client) CreateSourceNatRule(ctx context.Context, spec natRuleSpec) (string, error) {
	body, err := natWirePayload("source_nat", spec)
	if err != nil {
		return "", err
	}
	return c.natAdd(ctx, sourceNatEndpt.add, body)
}

// S3.6 — Update source NAT. POST /api/firewall/source_nat/set_rule/<uuid>.
func (c *Client) SetSourceNatRule(ctx context.Context, uuid string, spec natRuleSpec) error {
	body, err := natWirePayload("source_nat", spec)
	if err != nil {
		return err
	}
	return c.natSet(ctx, fmt.Sprintf(sourceNatEndpt.setFmt, uuid), body)
}

// S3.6 — Delete source NAT. POST /api/firewall/source_nat/del_rule/<uuid>.
func (c *Client) DeleteSourceNatRule(ctx context.Context, uuid string) error {
	return c.natSet(ctx, fmt.Sprintf(sourceNatEndpt.delFmt, uuid), []byte(`{}`))
}
