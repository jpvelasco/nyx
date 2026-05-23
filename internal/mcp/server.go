package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/velasco-jp/nyx/internal/audit"
	"github.com/velasco-jp/nyx/internal/backends/nmap"
	"github.com/velasco-jp/nyx/internal/backends/system"
	"github.com/velasco-jp/nyx/internal/intent"
	"github.com/velasco-jp/nyx/internal/models"
	"github.com/velasco-jp/nyx/internal/version"
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
					"subnet": {Type: "string", Description: "CIDR notation subnet to scan, e.g. 10.0.20.0/24"},
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
		result, err := nmap.Discover(ctx, subnet)
		if err != nil {
			return fmt.Sprintf("discovery failed: %v", err), true
		}
		return toJSON(result), false

	case "check_routes":
		target, _ := args["target"].(string)
		if target == "" {
			return "target parameter is required", true
		}
		route, err := system.GetRouteToTarget(ctx, target)
		if err != nil {
			return fmt.Sprintf("route check failed: %v", err), true
		}
		return toJSON(route), false

	case "check_vpn":
		target, _ := args["target"].(string)
		if target == "" {
			return "target parameter is required", true
		}
		route, err := system.GetRouteToTarget(ctx, target)
		if err != nil {
			return fmt.Sprintf("vpn check failed: %v", err), true
		}
		isVPN, _ := system.CheckVPNInterface(ctx, route.Device)
		result := map[string]interface{}{
			"target":     target,
			"device":     route.Device,
			"gateway":    route.Gateway,
			"via_tunnel": isVPN,
		}
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
