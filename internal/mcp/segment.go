package mcp

import (
	"context"
	"encoding/json"

	"github.com/jpvelasco/nyx/internal/service"
)

func segmentSchema(apply bool) inputSchema {
	props := map[string]propSchema{}
	for k, d := range map[string]string{"role": "Network role, used as the LAN and interface description", "parent": "OPNsense parent interface", "gateway": "New IPv4 gateway with prefix length", "management_prefix": "Protected management subnet", "resolver": "IPv4 DNS resolver", "pool_start": "First DHCP address", "pool_end": "Last DHCP address", "ssid": "Optional existing secured SSID to verify"} {
		props[k] = propSchema{Type: "string", Description: d}
	}
	props["tag"] = propSchema{Type: "integer", Description: "802.1Q VLAN tag from 1 through 4094"}
	if apply {
		props["dry_run"] = propSchema{Type: "boolean", Description: "Preview the steps. Defaults to true."}
	}
	addPlaybookCredentials(props)
	return inputSchema{Type: "object", Properties: props, Required: []string{"role", "parent", "tag", "gateway", "management_prefix", "resolver", "pool_start", "pool_end"}}
}
func (s *Server) toolPlanSegment(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	return s.segment(ctx, args, false)
}
func (s *Server) toolApplySegment(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	return s.segment(ctx, args, true)
}
func (s *Server) segment(ctx context.Context, args map[string]interface{}, apply bool) toolDispatchResult {
	if err := validateMutationArgs(args, segmentSchema(apply)); err != nil {
		return errResult(err.Error())
	}
	data, err := json.Marshal(args)
	if err != nil {
		return errResult("invalid segment arguments")
	}
	var req service.SegmentRequest
	if err = json.Unmarshal(data, &req); err != nil {
		return errResult("invalid segment field type")
	}
	if err = req.Validate(); err != nil {
		return errResult(err.Error())
	}
	opts, msg := s.playbookOptionsFromArgs(args)
	if msg != "" {
		return errResult(msg)
	}
	res, err := s.segmentSvc.Reconcile(ctx, opts, req, !apply || argBoolDefault(args, "dry_run", true))
	if err != nil {
		return errResult(err.Error())
	}
	return toolDispatchResult{text: toJSON(res), isErr: res.Attention() != nil}
}
