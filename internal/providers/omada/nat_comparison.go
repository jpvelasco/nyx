package omadaprovider

import (
	"strconv"
	"strings"

	"github.com/jpvelasco/nyx/internal/providers"
)

func newNATComparison(req providers.NatApplyRequest) providers.NatComparison {
	action := req.Action
	if action == "" {
		action = "create"
	}
	c := providers.NatComparison{Action: action, Path: omadaNatReadPath(req.Operation), Candidates: []string{}, Observation: "no_candidate_reported"}
	switch action {
	case "create":
		c.Method = "POST"
	case "update", "delete":
		c.Path += "/{ruleId}"
		c.Method = map[string]string{"update": "PUT", "delete": "DELETE"}[action]
	default:
		c.Path = "" // A dedicated toggle operation has no verified catalog contract.
	}
	if action != "create" {
		c.Observation = "selected_rule_missing"
	}
	c.Requested = map[string]string{}
	for k, v := range map[string]string{"rule_id": req.RuleUUID, "wan_interfaces": strings.Join(req.Spec.Interfaces, ","), "protocol": req.Spec.Protocol, "source": req.Spec.Source, "external_port": req.Spec.Port, "local_port": req.Spec.LocalPort, "target": req.Spec.Target, "external_address": req.Spec.Destination, "label": req.Spec.Label} {
		if v != "" {
			c.Requested[k] = v
		}
	}
	return c
}

func considerCandidate(c *providers.NatComparison, req providers.NatApplyRequest, id, name string, overlap bool) {
	if c.Action == "create" {
		if !overlap && (req.Spec.Label == "" || name != req.Spec.Label) {
			return
		}
	} else if req.RuleUUID != id {
		return
	}
	c.Candidates = append(c.Candidates, id)
	c.Observation = "inspect_candidate"
	if id == "" || len(c.Candidates) > 1 {
		c.Observation = "ambiguous_candidates"
	}
}

func protocolsMayOverlap(requested, observed string) bool {
	switch strings.ToLower(requested) {
	case "tcp":
		return !strings.EqualFold(observed, "udp")
	case "udp":
		return !strings.EqualFold(observed, "tcp")
	default:
		return true
	}
}

// Unknown port formats remain candidates because the controller may accept groups or lists.
func portsMayOverlap(left, right string) bool {
	bounds := func(value string) (int, int, bool) {
		start, end, pair := strings.Cut(value, "-")
		lo, err := strconv.Atoi(start)
		if !pair {
			end = start
		}
		hi, endErr := strconv.Atoi(end)
		return lo, hi, err == nil && endErr == nil && lo > 0 && hi >= lo && hi <= 65535
	}
	lo, hi, ok := bounds(left)
	otherLo, otherHi, otherOK := bounds(right)
	return !ok || !otherOK || lo <= otherHi && otherLo <= hi
}
