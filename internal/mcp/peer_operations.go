package mcp

import (
	"context"

	"github.com/jpvelasco/nyx/internal/service"
)

func wireGuardPeerBinding(apply bool) operationBinding {
	name, desc := "opnsense_plan_wireguard_peer", "Preview the allowed networks and overlap evidence for one peer change. Enrollment and access edits require operator administration."
	p := map[string]propSchema{"action": {Type: "string", Description: "create, update, toggle, or remove"}, "uuid": {Type: "string", Description: "Select exactly one existing peer by UUID"}, "enabled": {Type: "boolean", Description: "Explicit desired state for toggle"}}
	if apply {
		name, desc = "opnsense_revoke_wireguard_peer", "Disable or remove one selected peer and verify the readback. Defaults to preview."
		p["dry_run"] = propSchema{Type: "boolean", Description: "Preview revocation (default true)"}
	} else {
		withControllerTLS(p)
		p["name"] = propSchema{Type: "string", Description: "Peer name for a create preview"}
		p["allowed_networks"] = propSchema{Type: "string", Description: "Comma-separated desired canonical network prefixes"}
	}
	p["profile"] = propSchema{Type: "string", Description: "Configured OPNsense connection profile (default: default)"}
	return operationBinding{tool: tool{Name: name, Description: desc, InputSchema: inputSchema{Type: "object", Properties: p, Required: []string{"action"}}}, call: func(s *Server, ctx context.Context, args map[string]interface{}) toolDispatchResult {
		if err := validateMutationArgs(args, inputSchema{Properties: p}); err != nil {
			return errResult(err.Error())
		}
		opts, msg := s.opnsenseOptionsFromArgs(map[string]interface{}{"profile": argString(args, "profile")}, true)
		if msg != "" {
			return errResult("configure the selected OPNsense profile")
		}
		opts.SkipTLSVerify, opts.CACertPath = controllerTLS(args, s.env("NYX_OPNSENSE_CA_CERT"))
		req := service.WireGuardPeerRequest{Action: argString(args, "action"), UUID: argString(args, "uuid"), Name: argString(args, "name"), AllowedNetworks: splitCSV(argString(args, "allowed_networks"))}
		if enabled, ok := args["enabled"].(bool); ok {
			req.Enabled = &enabled
		}
		plan, err := service.NewOpnsenseService().RevokeWireGuardPeer(ctx, opts, req, !apply || argBoolDefault(args, "dry_run", true))
		return peerResult(plan, err)
	}}
}

func approvedPeerBinding() operationBinding {
	return operationBinding{tool: tool{Name: "opnsense_apply_approved_wireguard_peer", Description: "Preview or reconcile the exact peer state supplied by the operator in the Nyx process configuration.", InputSchema: inputSchema{Type: "object", Properties: map[string]propSchema{"dry_run": {Type: "boolean", Description: "Preview the approved peer state (default true)"}}}}, call: func(s *Server, ctx context.Context, args map[string]interface{}) toolDispatchResult {
		dry := true
		for k, val := range args {
			if k != "dry_run" {
				return errResult("only dry_run is accepted for this operator-approved change")
			}
			var ok bool
			dry, ok = val.(bool)
			if !ok {
				return errResult("dry_run must be a boolean")
			}
		}
		approval, err := service.LoadApprovedPeer(s.env(service.PeerApprovalEnv))
		if err != nil {
			return errResult(err.Error())
		}
		opts, msg := s.opnsenseOptionsFromArgs(map[string]interface{}{"profile": approval.Profile}, true)
		if msg != "" {
			return errResult("configure the approved OPNsense profile")
		}
		plan, err := service.NewOpnsenseService().ApplyApprovedPeer(ctx, opts, approval, dry)
		return peerResult(plan, err)
	}}
}

func peerResult(plan *service.WireGuardPeerPlan, err error) toolDispatchResult {
	if err != nil {
		if plan != nil {
			return errResult(toJSON(map[string]any{"plan": plan, "error": err.Error()}))
		}
		return errResult(err.Error())
	}
	return okResult(toJSON(plan))
}
