package mcp

import (
	"context"

	"github.com/jpvelasco/nyx/internal/service"
)

func clientLocationBinding() operationBinding {
	schema := networkMapSchema()
	schema.Properties["mac"] = propSchema{Type: "string", Description: "Client MAC to look up in the selected controller inventories."}
	schema.Required = []string{"mac"}
	return operationBinding{tool: tool{Name: service.ClientLocationTool, Description: "Locate one client using passive switch, wireless, lease and neighbor evidence. Reports the nearest visible managed uplink and labels stale or conflicting evidence.", InputSchema: schema}, call: func(s *Server, ctx context.Context, args map[string]interface{}) toolDispatchResult {
		opts, err := s.mapOptions(args)
		if err != nil {
			return errResult(err.Error())
		}
		result, err := service.NewTopologyService().LocateClient(ctx, opts, argString(args, "mac"))
		if err != nil {
			return errResult(err.Error())
		}
		return untrustedDataResult(result, "Client attachment data")
	}}
}
