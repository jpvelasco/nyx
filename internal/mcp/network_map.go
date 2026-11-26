package mcp

import (
	"context"
	"os"

	"github.com/jpvelasco/nyx/internal/service"
)

func networkMapBinding() operationBinding {
	return operationBinding{tool: tool{
		Name:        service.NetworkMapTool,
		Description: "Map devices, switch ports, VLANs, SSIDs and serving gateways from configured provider inventories. Links include their evidence and uncertainty. Read-only.",
		InputSchema: inputSchema{Type: "object", Properties: map[string]propSchema{
			"connections":     {Type: "array", Items: &propSchema{Type: "string"}, Description: "Provider or provider/profile selectors. Omit to observe configured connections."},
			"include_detail":  {Type: "boolean", Description: "Include private identifiers and addresses with operator opt-in via NYX_MCP_ALLOW_TOPOLOGY_DETAILS=true."},
			"ca_cert_path":    {Type: "string", Description: "Path to a custom controller CA certificate."},
			"skip_tls_verify": {Type: "boolean", Description: "Skip controller TLS certificate verification."},
		}},
	}, call: (*Server).toolNetworkMap}
}

func (s *Server) toolNetworkMap(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	var opts service.NetworkMapOptions
	if raw, ok := args["connections"]; ok {
		values, valid := raw.([]interface{})
		if !valid || len(values) == 0 {
			return errResult("connections must be a nonempty array of provider/profile selectors")
		}
		for _, v := range values {
			selector, ok := v.(string)
			if !ok || selector == "" {
				return errResult("each connection must be a provider/profile selector")
			}
			opts.Connections = append(opts.Connections, selector)
		}
	}
	opts.Detail, _ = args["include_detail"].(bool)
	if opts.Detail && os.Getenv("NYX_MCP_ALLOW_TOPOLOGY_DETAILS") != "true" {
		return errResult("network map detail requires operator opt-in via NYX_MCP_ALLOW_TOPOLOGY_DETAILS=true")
	}
	opts.SkipTLSVerify, _ = args["skip_tls_verify"].(bool)
	opts.CACertPath = argString(args, "ca_cert_path")
	opts.Logger = s.logger
	result, err := service.NewTopologyService().Map(ctx, opts)
	if err != nil {
		return errResult(err.Error())
	}
	return untrustedDataResult(result, "Network map data")
}
