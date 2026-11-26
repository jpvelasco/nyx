package mcp

import (
	"context"

	"github.com/jpvelasco/nyx/internal/service"
)

func switchPortsBinding() operationBinding {
	schema := networkMapSchema()
	delete(schema.Properties, "connections")
	delete(schema.Properties, "include_detail")
	schema.Properties["connection"] = propSchema{Type: "string", Description: "Omada provider/profile selected for the switch."}
	schema.Properties["switch_mac"] = propSchema{Type: "string", Description: "MAC of the managed switch."}
	schema.Properties["policy"] = propSchema{Type: "string", Description: "JSON containing management_vlan and ports. Each port specifies port, role, native, tagged and for access ports client_mac."}
	schema.Required = []string{"connection", "switch_mac", "policy"}
	return operationBinding{tool: tool{Name: service.SwitchPortsTool, Description: "Compare observed port use against operator-supplied VLAN intent. Read-only. Eligible rows can be applied individually using the original switch selector and expected revision.", InputSchema: schema}, call: func(s *Server, ctx context.Context, args map[string]interface{}) toolDispatchResult {
		policy, err := service.DecodeSwitchPortPolicy(argString(args, "policy"))
		if err != nil {
			return errResult(err.Error())
		}
		opts, err := s.mapOptions(args)
		if err != nil {
			return errResult(err.Error())
		}
		result, err := service.NewTopologyService().PlanSwitchPorts(ctx, opts, argString(args, "connection"), argString(args, "switch_mac"), policy)
		if err != nil {
			return errResult(err.Error())
		}
		return untrustedDataResult(result, "Switch port plan")
	}}
}
