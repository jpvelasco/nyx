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
		p["name"] = propSchema{Type: "string", Description: "Peer name for a create preview"}
		p["allowed_networks"] = propSchema{Type: "string", Description: "Comma-separated desired canonical network prefixes"}
	}
	return operationBinding{tool: tool{Name: name, Description: desc, InputSchema: opnsenseToolSchemaExtra(p, []string{"action"})}, call: func(s *Server, ctx context.Context, args map[string]interface{}) toolDispatchResult {
		opts, msg := s.opnsenseOptionsFromArgs(args, true)
		if msg != "" {
			return errResult(msg)
		}
		req := service.WireGuardPeerRequest{Action: argString(args, "action"), UUID: argString(args, "uuid"), Name: argString(args, "name"), AllowedNetworks: splitCSV(argString(args, "allowed_networks"))}
		if raw, ok := args["enabled"]; ok {
			v, ok := raw.(bool)
			if !ok {
				return errResult("enabled must be a boolean")
			}
			req.Enabled = &v
		}
		dry := true
		if raw, ok := args["dry_run"]; ok && apply {
			v, ok := raw.(bool)
			if !ok {
				return errResult("dry_run must be a boolean")
			}
			dry = v
		}
		plan, err := service.NewOpnsenseService().RevokeWireGuardPeer(ctx, opts, req, dry)
		if err != nil {
			if plan != nil {
				return errResult(toJSON(map[string]any{"error": err.Error(), "plan": plan}))
			}
			return errResult(err.Error())
		}
		return okResult(toJSON(plan))
	}}
}
