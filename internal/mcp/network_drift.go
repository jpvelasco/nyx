package mcp

import (
	"context"
	"github.com/jpvelasco/nyx/internal/service"
)

func mapCaptureBinding() operationBinding {
	schema := networkMapSchema()
	delete(schema.Properties, "include_detail")
	schema.Required = []string{"name"}
	schema.Properties["name"] = propSchema{Type: "string", Description: "Name of the map to save in the private Nyx snapshot store."}
	schema.Properties["replace"] = propSchema{Type: "boolean", Description: "Replace an existing capture with this name; default false."}
	schema.Properties["audit_snapshot"] = propSchema{Type: "string", Description: "Optional audit snapshot basename for declared service policies."}
	return operationBinding{tool: tool{Name: service.MapCaptureTool, Description: "Capture a private map locally for drift comparison. Returns the capture time.", InputSchema: schema}, call: func(s *Server, ctx context.Context, args map[string]interface{}) toolDispatchResult {
		opts, err := s.mapOptions(args)
		if err != nil {
			return errResult(err.Error())
		}
		receipt, err := service.NewTopologyService().CaptureMap(ctx, opts, argString(args, "name"), argString(args, "audit_snapshot"), argBoolDefault(args, "replace", false))
		if err != nil {
			return errResult(err.Error())
		}
		return untrustedDataResult(receipt, "Map capture")
	}}
}
func mapDriftBinding() operationBinding {
	schema := networkMapSchema()
	delete(schema.Properties, "include_detail")
	schema.Required = []string{"before"}
	for key, desc := range map[string]string{"before": "Name of the earlier map snapshot.", "after": "Name of the later map; omit for a current read.", "max_age": "Maximum observation age when each map was captured, default 24h.", "audit_snapshot": "Optional audit snapshot basename for current policy observations."} {
		schema.Properties[key] = propSchema{Type: "string", Description: desc}
	}
	return operationBinding{tool: tool{Name: service.MapDriftTool, Description: "Compare maps and report changes with stable references. Reads preserve local baselines.", InputSchema: schema}, call: func(s *Server, ctx context.Context, args map[string]interface{}) toolDispatchResult {
		opts, err := s.mapOptions(args)
		if err != nil {
			return errResult(err.Error())
		}
		report, err := service.NewTopologyService().MapDrift(ctx, opts, argString(args, "before"), argString(args, "after"), argString(args, "audit_snapshot"), argString(args, "max_age"))
		if err != nil {
			return errResult(err.Error())
		}
		return untrustedDataResult(report, "Network map drift")
	}}
}
