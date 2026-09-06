package opnsense

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jpvelasco/nyx/internal/topology"
)

// natOperation describes one supported NAT mutation collection: its client
// collection key and the exact API paths it touches (evidence + warnings).
type natOperation struct {
	coll   string
	create string
	set    string
	del    string
	toggle string
	list   func(*Client, context.Context) ([]NatRule, error)
}

// natOperations maps each supported mutation operation to its collection
// and wire paths. The endpoints are the wire truth for evidence.
var natOperations = map[string]natOperation{
	"port_forward": {
		coll:   "port_forward",
		create: "/firewall/d_nat/add_rule",
		set:    "/firewall/d_nat/set_rule/%s",
		del:    "/firewall/d_nat/del_rule/%s",
		toggle: "/firewall/d_nat/toggle_rule/<uuid>,<disabled>",
		list:   (*Client).GetPortForwardRules,
	},
	"one_to_one": {
		coll:   "one_to_one",
		create: "/firewall/one_to_one/add_rule",
		set:    "/firewall/one_to_one/set_rule/%s",
		del:    "/firewall/one_to_one/del_rule/%s",
		toggle: "/firewall/one_to_one/toggle_rule/<uuid>,<enabled>",
		list:   (*Client).GetOneToOneRules,
	},
	"source_nat": {
		coll:   "source_nat",
		create: "/firewall/source_nat/add_rule",
		set:    "/firewall/source_nat/set_rule/%s",
		del:    "/firewall/source_nat/del_rule/%s",
		toggle: "/firewall/source_nat/toggle_rule/<uuid>,<enabled>",
		list:   (*Client).GetSourceNatRules,
	},
}

// natGuardOutcome is the double-NAT guard verdict for one NAT mutation: the
// classified role plus the evidence trail.
type natGuardOutcome struct {
	role     topology.NatRole
	evidence []string
}

// natGuardTimeout bounds the guard's read-only POSTs (outbound mode + the
// three rule lists). A healthy controller answers in well under a second, so
// a 10s cap fails fast when the API is unreachable instead of the per-request
// retry budget multiplying the 15s HTTP timeout. POSTs never touch this path.
const natGuardTimeout = 10 * time.Second

// natGuard reads the device's NAT posture (outbound mode + rule counts) and
// classifies it for the double-NAT guard. The reads are GETs only — allowed
// under dry-run.
func (c *Client) natGuard(ctx context.Context) (*natGuardOutcome, error) {
	mode, err := c.GetOutboundNatMode(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading outbound NAT mode: %w", err)
	}
	pf, err := c.GetPortForwardRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading port forward rules: %w", err)
	}
	o2o, err := c.GetOneToOneRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading one-to-one rules: %w", err)
	}
	snat, err := c.GetSourceNatRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading source NAT rules: %w", err)
	}
	role, evidence := topology.Classify(topology.DeviceFacts{
		Provider:         topology.ProviderOpnsense,
		OutboundNatMode:  mode,
		SourceNatRules:   len(snat),
		PortForwardRules: len(pf),
		OneToOneRules:    len(o2o),
	})
	return &natGuardOutcome{role: role, evidence: evidence}, nil
}

// natGuardWarning builds the refusal warning for a refused NAT mutation, or
// "" when the guard passes. An unknown device is refused even with
// allow_double_nat — the flag never overrides an unmeasured risk.
func (g *natGuardOutcome) natGuardWarning(allowDoubleNat bool) string {
	switch g.role {
	case topology.RoleUnknown:
		return "double-NAT guard: outbound NAT mode is unknown — the controller did not report a recognised " +
			"snat_mode (key drift across versions); the risk was not measured and cannot be consented to, so the " +
			"mutation is refused. Resolve the mode (or file a provider issue) before allowing NAT mutations."
	case topology.RoleBridge, topology.RoleIndeterminate:
		if allowDoubleNat {
			return ""
		}
		what := "a bridge (transparent for outbound NAT)"
		if g.role == topology.RoleIndeterminate {
			what = "indeterminate (conflicting NAT facts)"
		}
		return fmt.Sprintf("double-NAT guard: device is %s; NAT mutations are refused unless allow_double_nat is set. Evidence: %v", what, g.evidence)
	default:
		return ""
	}
}

// natStagedWarning is the staged-vs-live fact every PlanNat result (and
// every dry-run / refused / unchanged ApplyNat) carries: the write, if
// any, is config.xml only until firewall/filter/apply commits it.
const natStagedWarning = "OPNsense NAT changes are staged (config.xml) and are not in the dataplane until the " +
	"controller applies them; no traffic is affected by this call. Verify with a follow-up read."

// natAppliedWarning is the live-dataplane fact a real ApplyNat carries
// after firewall/filter/apply succeeds (S3.9).
const natAppliedWarning = "OPNsense NAT change was committed to the dataplane via firewall/filter/apply."

// filterApplyPath is the 26.x activate step inherited from filter_base.
// Do not revive the dead /firewall/filter_base/apply path.
const filterApplyPath = "/firewall/filter/apply"

// marshalRules marshals a NAT rule list to JSON for Before/After evidence.
// An empty list marshals as "[]", never "null".
func marshalRules(rules []NatRule) string {
	if len(rules) == 0 {
		return "[]"
	}
	b, err := json.Marshal(rules)
	if err != nil {
		return "[]"
	}
	return string(b)
}
