package mcp

import (
	"context"
	"github.com/jpvelasco/nyx/internal/service"
)

func performanceBinding() operationBinding {
	schema := networkMapSchema()
	delete(schema.Properties, "connections")
	delete(schema.Properties, "include_detail")
	schema.Properties["path"] = propSchema{Type: "string", Description: "JSON array in path order. Each hop selects connection (provider/profile) and kind. switch_port takes switch_mac and port, channel takes band, channel and an optional ap_mac for interference, interface/gateway/shaper_queue take name."}
	schema.Properties["interval"] = propSchema{Type: "string", Description: "Requested time between two passive samples; 1s through 1m, default 5s."}
	schema.Required = []string{"path"}
	return operationBinding{tool: tool{Name: service.PerformanceTool, Description: "Sample read-only counters and report current error, utilization and gateway evidence on the selected path. Repeat the same path and interval after a change.", InputSchema: schema}, call: func(s *Server, ctx context.Context, args map[string]interface{}) toolDispatchResult {
		o, err := s.mapOptions(args)
		if err != nil {
			return errResult(err.Error())
		}
		r, err := service.SamplePerformance(ctx, o, argString(args, "path"), argString(args, "interval"))
		if err != nil {
			return errResult(err.Error())
		}
		return untrustedDataResult(r, "Path performance")
	}}
}
