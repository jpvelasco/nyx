package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/jpvelasco/nyx/internal/credentials"
	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/jpvelasco/nyx/internal/storepath"
)

type operationBinding struct {
	tool tool
	call toolHandler
}

func sharedBindings() []operationBinding {
	out := []operationBinding{capabilityBinding()}
	for _, adapter := range providers.Adapters() {
		if op, ok := service.ControllerInfo(adapter); ok {
			out = append(out, infoBinding(op))
		}
	}
	return out
}

func infoBinding(op service.InfoOperation) operationBinding {
	t := infoTool(op)
	return operationBinding{tool: t, call: func(s *Server, ctx context.Context, args map[string]interface{}) toolDispatchResult {
		opts, msg := s.providerInfoOptions(op, args)
		if msg != "" {
			return errResult(msg)
		}
		selected := op
		if s.readInfo != nil {
			selected.InfoReader = infoReadFunc(func(ctx context.Context, opts providers.ImportOptions) (*providers.ProviderInfo, error) {
				return s.readInfo(ctx, op, opts)
			})
		}
		info, err := selected.Read(ctx, opts)
		if err != nil {
			message := err.Error()
			// The original Omada tool reported the lower-level controller error directly.
			if op.Provider == "omada" {
				message = strings.TrimPrefix(message, "connecting to omada controller: ")
			}
			return errResult(fmt.Sprintf("%s info request failed: %s", op.Provider, message))
		}
		return okResult(toJSON(op.AgentInfo(info)))
	}}
}

type infoReadFunc func(context.Context, providers.ImportOptions) (*providers.ProviderInfo, error)

func (f infoReadFunc) Info(ctx context.Context, opts providers.ImportOptions) (*providers.ProviderInfo, error) {
	return f(ctx, opts)
}

func (s *Server) providerInfoOptions(op service.InfoOperation, args map[string]interface{}) (providers.ImportOptions, string) {
	fields, msg := s.connectionFields(op.Provider, args, op.Authenticated)
	opts := providers.ConnectionOptions(credentials.Connection{Provider: op.Provider, Profile: argString(args, "profile")}, fields)
	opts.SkipTLSVerify, _ = args["skip_tls_verify"].(bool)
	opts.CACertPath = argString(args, "ca_cert_path")
	opts.Logger = s.logger
	return opts, msg
}

func infoTool(op service.InfoOperation) tool {
	switch op.Provider {
	case "omada":
		return tool{
			Name:        op.MCPName,
			Description: "Fetch metadata (version, API version, omada CID) from an Omada SDN controller without authentication.",
			InputSchema: inputSchema{
				Type: "object",
				Properties: map[string]propSchema{
					"profile":         {Type: "string", Description: "Named Omada credential profile"},
					"host":            {Type: "string", Description: "Omada controller hostname or IP"},
					"skip_tls_verify": {Type: "boolean", Description: "Skip TLS certificate verification (self-signed certs)"},
					"ca_cert_path":    {Type: "string", Description: "Path to a CA certificate for the controller"},
				},
				Required: nil,
			},
		}
	case "opnsense":
		return tool{
			Name:        op.MCPName,
			Description: "Fetch system metadata (version, product, arch) from an OPNsense firewall. Reads the Dashboard-privileged system-information endpoint (no System: Firmware privilege required).",
			InputSchema: opnsenseToolSchema(),
		}
	default:
		schema := inputSchema{Type: "object", Properties: map[string]propSchema{
			"profile":         {Type: "string", Description: "Named credential profile"},
			"host":            {Type: "string", Description: "Controller host"},
			"skip_tls_verify": {Type: "boolean", Description: "Skip TLS certificate verification"},
			"ca_cert_path":    {Type: "string", Description: "Path to a CA certificate"},
		}}
		for _, field := range credentials.FieldsFor(op.Provider) {
			schema.Properties[field.Name] = propSchema{Type: "string", Description: field.Description}
		}
		return tool{Name: op.MCPName, Description: "Read controller information from " + op.Provider, InputSchema: schema}
	}
}

func capabilityBinding() operationBinding {
	schema := inputSchema{Type: "object", Properties: map[string]propSchema{
		"provider":        {Type: "string", Description: "Limit results to this adapter"},
		"profile":         {Type: "string", Description: "Limit results to this connection profile"},
		"observe":         {Type: "boolean", Description: "Verify controller information access (default false)"},
		"skip_tls_verify": {Type: "boolean", Description: "Skip TLS certificate verification"},
		"ca_cert_path":    {Type: "string", Description: "Path to a CA certificate"},
	}}
	return operationBinding{tool: tool{Name: service.CapabilitiesTool, Description: "List adapter operations and configured sites and profiles. Set observe to verify controller information access with a read-only request.", InputSchema: schema}, call: func(s *Server, ctx context.Context, args map[string]interface{}) toolDispatchResult {
		opts := service.CapabilityOptions{
			Provider:      argString(args, "provider"),
			Profile:       argString(args, "profile"),
			Observe:       argBoolDefault(args, "observe", false),
			SkipTLSVerify: argBoolDefault(args, "skip_tls_verify", false),
			CACertPath:    argString(args, "ca_cert_path"),
		}
		report, err := service.ProviderCapabilityReport(ctx, opts, storepath.StoreFile(), s.env)
		if err != nil {
			return errResult(err.Error())
		}
		return okResult(toJSON(report))
	}}
}
