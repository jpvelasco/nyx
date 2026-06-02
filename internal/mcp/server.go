// Package mcp implements the Model Context Protocol (MCP) stdio server for exposing nyx capabilities to AI agents.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/jpvelasco/nyx/internal/audit"
	"github.com/jpvelasco/nyx/internal/backends/nmap"
	"github.com/jpvelasco/nyx/internal/backends/system"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/version"
)

// JSON-RPC types
type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// MCP types
type serverInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type initializeResult struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities"`
	ServerInfo      serverInfo             `json:"serverInfo"`
}

type tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema inputSchema `json:"inputSchema"`
}

type inputSchema struct {
	Type       string                `json:"type"`
	Properties map[string]propSchema `json:"properties"`
	Required   []string              `json:"required,omitempty"`
}

type propSchema struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

type toolsListResult struct {
	Tools []tool `json:"tools"`
}

type toolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

type toolCallResult struct {
	Content []contentBlock `json:"content"`
	IsError bool           `json:"isError,omitempty"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Server is the MCP stdio server
type Server struct {
	reader io.Reader
	writer io.Writer
}

// NewServer creates a new MCP server
func NewServer() *Server {
	return &Server{
		reader: os.Stdin,
		writer: os.Stdout,
	}
}

// Serve runs the MCP server loop on stdio
func (s *Server) Serve(ctx context.Context) error {
	scanner := bufio.NewScanner(s.reader)
	// Increase buffer for large messages
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}

		var req jsonRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			// Skip malformed messages
			continue
		}

		// Notifications have no ID and need no response
		if req.ID == nil || string(req.ID) == "null" {
			// Handle notification silently
			continue
		}

		resp := s.handleRequest(ctx, &req)
		respBytes, err := json.Marshal(resp)
		if err != nil {
			continue
		}
		fmt.Fprintf(s.writer, "%s\n", respBytes)
	}
	return scanner.Err()
}

func (s *Server) handleRequest(ctx context.Context, req *jsonRPCRequest) *jsonRPCResponse {
	switch req.Method {
	case "initialize":
		return s.handleInitialize(req)
	case "tools/list":
		return s.handleToolsList(req)
	case "tools/call":
		return s.handleToolCall(ctx, req)
	default:
		return &jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &rpcError{Code: -32601, Message: fmt.Sprintf("method not found: %s", req.Method)},
		}
	}
}

func (s *Server) handleInitialize(req *jsonRPCRequest) *jsonRPCResponse {
	return &jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: initializeResult{
			ProtocolVersion: "2024-11-05",
			Capabilities: map[string]interface{}{
				"tools": map[string]interface{}{},
			},
			ServerInfo: serverInfo{
				Name:    "nyx",
				Version: version.Version,
			},
		},
	}
}

func (s *Server) handleToolsList(req *jsonRPCRequest) *jsonRPCResponse {
	tools := []tool{
		{
			Name:        "discover_subnet",
			Description: "Discover active hosts in a subnet using nmap ping sweep.",
			InputSchema: inputSchema{
				Type: "object",
				Properties: map[string]propSchema{
					"subnet":        {Type: "string", Description: "CIDR notation subnet to scan, e.g. 192.168.1.0/24"},
					"scan_timing":   {Type: "number", Description: "nmap -T timing template (0-5, default 4)"},
					"scan_min_rate": {Type: "number", Description: "nmap --min-rate packets/sec (default 500)"},
				},
				Required: []string{"subnet"},
			},
		},
		{
			Name:        "check_routes",
			Description: "Check the routing path to a target IP address.",
			InputSchema: inputSchema{
				Type: "object",
				Properties: map[string]propSchema{
					"target": {Type: "string", Description: "Target IP address to check route for"},
				},
				Required: []string{"target"},
			},
		},
		{
			Name:        "check_vpn",
			Description: "Check if traffic to a target is routed through a VPN tunnel interface.",
			InputSchema: inputSchema{
				Type: "object",
				Properties: map[string]propSchema{
					"target":   {Type: "string", Description: "Target IP to check VPN routing for"},
					"vpn_name": {Type: "string", Description: "Optional VPN name to match against"},
				},
				Required: []string{"target"},
			},
		},
		{
			Name:        "verify_isolation",
			Description: "Verify network isolation between two zones using a spec file.",
			InputSchema: inputSchema{
				Type: "object",
				Properties: map[string]propSchema{
					"from":      {Type: "string", Description: "Source zone or network name"},
					"to":        {Type: "string", Description: "Destination zone or network name"},
					"spec_file": {Type: "string", Description: "Optional path to YAML spec file"},
				},
				Required: []string{"from", "to"},
			},
		},
		{
			Name:        "run_audit",
			Description: "Run a full audit from a YAML spec file.",
			InputSchema: inputSchema{
				Type: "object",
				Properties: map[string]propSchema{
					"spec_file": {Type: "string", Description: "Path to YAML spec file"},
				},
				Required: []string{"spec_file"},
			},
		},
		{
			Name:        "load_spec",
			Description: "Load and validate a YAML spec file, returning parsed content.",
			InputSchema: inputSchema{
				Type: "object",
				Properties: map[string]propSchema{
					"spec_file": {Type: "string", Description: "Path to YAML spec file"},
				},
				Required: []string{"spec_file"},
			},
		},
		{
			Name:        "get_interfaces",
			Description: "List all network interfaces and their addresses.",
			InputSchema: inputSchema{
				Type:       "object",
				Properties: map[string]propSchema{},
			},
		},
		{
			Name:        "ping_target",
			Description: "Ping a target IP and return reachability status.",
			InputSchema: inputSchema{
				Type: "object",
				Properties: map[string]propSchema{
					"target": {Type: "string", Description: "Target IP address to ping"},
				},
				Required: []string{"target"},
			},
		},
		{
			Name:        "run_doctor",
			Description: "Check nyx environment health. Optionally validate a spec file.",
			InputSchema: inputSchema{
				Type: "object",
				Properties: map[string]propSchema{
					"spec_file": {Type: "string", Description: "Optional path to a YAML spec file to validate"},
				},
			},
		},
		{
			Name:        "provider_list",
			Description: "List all registered providers and their capabilities.",
			InputSchema: inputSchema{
				Type:       "object",
				Properties: map[string]propSchema{},
			},
		},
	}

	return &jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  toolsListResult{Tools: tools},
	}
}

func (s *Server) handleToolCall(ctx context.Context, req *jsonRPCRequest) *jsonRPCResponse {
	var params toolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return &jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &rpcError{Code: -32602, Message: "invalid params"},
		}
	}

	resultText, isError := s.dispatchTool(ctx, params.Name, params.Arguments)
	return &jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: toolCallResult{
			Content: []contentBlock{{Type: "text", Text: resultText}},
			IsError: isError,
		},
	}
}

func (s *Server) dispatchTool(ctx context.Context, name string, args map[string]interface{}) (string, bool) {
	switch name {
	case "discover_subnet":
		subnet, _ := args["subnet"].(string)
		if subnet == "" {
			return "subnet parameter is required", true
		}
		opts := nmap.DefaultScanOptions
		if t, ok := args["scan_timing"].(float64); ok && t > 0 {
			opts.TimingTemplate = int(t)
		}
		if r, ok := args["scan_min_rate"].(float64); ok && r > 0 {
			opts.MinRate = int(r)
		}
		result, err := nmap.DiscoverWithOptions(ctx, subnet, opts)
		if err != nil {
			return fmt.Sprintf("discovery failed: %v", err), true
		}
		return toJSON(result), false

	case "check_routes":
		target, _ := args["target"].(string)
		if target == "" {
			return "target parameter is required", true
		}
		result := models.NewCheckResult("system", "route_check", "local", target)
		route, err := system.GetRouteToTarget(ctx, target)
		if err != nil {
			result.Status = models.StatusError
			result.Summary = fmt.Sprintf("failed to get route to %s: %v", target, err)
			result.Finish()
			return toJSON(result), true
		}
		result.Observed["gateway"] = route.Gateway
		result.Observed["device"] = route.Device
		result.Status = models.StatusPass
		result.Summary = fmt.Sprintf("route to %s via %s dev %s", target, route.Gateway, route.Device)
		result.Finish()
		return toJSON(result), false

	case "check_vpn":
		target, _ := args["target"].(string)
		if target == "" {
			return "target parameter is required", true
		}
		result := models.NewCheckResult("system", "vpn_route", "local", target)
		route, err := system.GetRouteToTarget(ctx, target)
		if err != nil {
			result.Status = models.StatusError
			result.Summary = fmt.Sprintf("failed to get route to %s: %v", target, err)
			result.Finish()
			return toJSON(result), true
		}
		result.Observed["device"] = route.Device
		result.Observed["gateway"] = route.Gateway
		isVPN, _ := system.CheckVPNInterface(ctx, route.Device)
		result.Observed["via_tunnel"] = isVPN
		if isVPN {
			result.Status = models.StatusPass
			result.Summary = fmt.Sprintf("%s routes via tunnel (%s)", target, route.Device)
		} else {
			result.Status = models.StatusWarn
			result.Summary = fmt.Sprintf("%s routes via %s (not a tunnel interface)", target, route.Device)
		}
		result.Finish()
		return toJSON(result), false

	case "verify_isolation":
		from, _ := args["from"].(string)
		to, _ := args["to"].(string)
		if from == "" {
			return "from parameter is required", true
		}
		if to == "" {
			return "to parameter is required", true
		}
		specFile, _ := args["spec_file"].(string)

		if specFile != "" {
			spec, err := intent.LoadSpec(specFile)
			if err != nil {
				return fmt.Sprintf("failed to load spec: %v", err), true
			}
			expectDeny := "deny"
			miniSpec := &intent.Spec{
				Version:  spec.Version,
				Site:     spec.Site,
				Networks: spec.Networks,
				Assertions: []intent.Assertion{{
					Type:       "isolation",
					From:       from,
					To:         to,
					ExpectDeny: expectDeny,
				}},
			}
			eng := audit.NewEngine(miniSpec)
			report, err := eng.Run(ctx)
			if err != nil {
				return fmt.Sprintf("isolation check failed: %v", err), true
			}
			if len(report.Findings) == 0 {
				return "no findings returned", true
			}
			return toJSON(report.Findings[0]), false
		}

		// No spec: ping `to` directly as a bare IP/hostname
		result := models.NewCheckResult("system", "isolation", "local", fmt.Sprintf("%s -> %s", from, to))
		pingResult, err := system.Ping(ctx, to)
		if err != nil {
			result.Status = models.StatusWarn
			result.Summary = fmt.Sprintf("could not determine isolation: %v", err)
		} else {
			result.Observed["reachable"] = pingResult.Reachable
			if pingResult.Reachable {
				result.Status = models.StatusFail
				result.Summary = fmt.Sprintf("isolation violated: %s can reach %s", from, to)
				result.Violations = append(result.Violations, "target is reachable when isolation is expected")
			} else {
				result.Status = models.StatusPass
				result.Summary = fmt.Sprintf("isolation confirmed: %s cannot reach %s", from, to)
			}
		}
		result.Finish()
		return toJSON(result), false

	case "run_audit":
		specFile, _ := args["spec_file"].(string)
		if specFile == "" {
			return "spec_file parameter is required", true
		}
		spec, err := intent.LoadSpec(specFile)
		if err != nil {
			return fmt.Sprintf("failed to load spec: %v", err), true
		}
		eng := audit.NewEngine(spec)
		report, err := eng.Run(ctx)
		if err != nil {
			return fmt.Sprintf("audit failed: %v", err), true
		}
		return toJSON(report), false

	case "load_spec":
		specFile, _ := args["spec_file"].(string)
		if specFile == "" {
			return "spec_file parameter is required", true
		}
		spec, err := intent.LoadSpec(specFile)
		if err != nil {
			return fmt.Sprintf("failed to load spec: %v", err), true
		}
		return toJSON(spec), false

	case "get_interfaces":
		ifaces, err := system.GetInterfaces(ctx)
		if err != nil {
			return fmt.Sprintf("failed to get interfaces: %v", err), true
		}
		return toJSON(ifaces), false

	case "ping_target":
		target, _ := args["target"].(string)
		if target == "" {
			return "target parameter is required", true
		}
		pingResult, err := system.Ping(ctx, target)
		if err != nil {
			return fmt.Sprintf("ping failed: %v", err), true
		}
		return toJSON(pingResult), false

	case "run_doctor":
		specPath, _ := args["spec_file"].(string)
		var findings []models.CheckResult

		nmapResult := models.NewCheckResult("doctor", "nmap_installed", "local", "nmap")
		if nmap.Available() {
			nmapResult.Status = models.StatusPass
			nmapResult.Summary = "nmap is available"
		} else {
			nmapResult.Status = models.StatusFail
			nmapResult.Summary = "nmap is not installed or not in PATH"
		}
		nmapResult.Finish()
		findings = append(findings, *nmapResult)

		if specPath != "" {
			data, err := os.ReadFile(specPath)
			if err != nil {
				fileCheck := models.NewCheckResult("doctor", "spec_file", "local", specPath)
				fileCheck.Status = models.StatusFail
				fileCheck.Summary = fmt.Sprintf("cannot read spec file: %v", err)
				fileCheck.Finish()
				findings = append(findings, *fileCheck)
			} else {
				fileCheck := models.NewCheckResult("doctor", "spec_file", "local", specPath)
				fileCheck.Status = models.StatusPass
				fileCheck.Summary = fmt.Sprintf("spec file readable (%d bytes)", len(data))
				fileCheck.Finish()
				findings = append(findings, *fileCheck)

				validCheck := models.NewCheckResult("doctor", "spec_valid", "local", specPath)
				if _, err := intent.ParseSpec(data); err != nil {
					validCheck.Status = models.StatusFail
					validCheck.Summary = fmt.Sprintf("spec invalid: %v", err)
				} else {
					validCheck.Status = models.StatusPass
					validCheck.Summary = "spec is valid"
				}
				validCheck.Finish()
				findings = append(findings, *validCheck)
			}
		}

		doctorReport := &models.AuditReport{
			Audit:    "doctor",
			Status:   models.ComputeOverallStatus(findings),
			Summary:  models.Tally(findings),
			Findings: findings,
		}
		return toJSON(doctorReport), false

	case "provider_list":
		list := providers.List()
		type entry struct {
			Name         string   `json:"name"`
			Capabilities []string `json:"capabilities"`
		}
		out := make([]entry, len(list))
		for i, p := range list {
			out[i] = entry{Name: p.Name(), Capabilities: p.Capabilities()}
		}
		return toJSON(out), false

	default:
		return fmt.Sprintf("unknown tool: %s", name), true
	}
}

// DispatchToolForTest exposes dispatchTool for testing.
func (s *Server) DispatchToolForTest(ctx context.Context, name string, args map[string]interface{}) (string, bool) {
	return s.dispatchTool(ctx, name, args)
}

func toJSON(v interface{}) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("json marshal error: %v", err)
	}
	return string(b)
}
