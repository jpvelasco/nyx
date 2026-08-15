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
	"github.com/jpvelasco/nyx/internal/service"
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

// omadaSurface is the Omada observation and read-only planning surface
// exposed to agents, plus the dry-run-default ACL mutation tool.
type omadaSurface interface {
	Info(ctx context.Context, opts service.OmadaOptions) (*service.OmadaInfo, error)
	ListNetworks(ctx context.Context, opts service.OmadaOptions) ([]service.OmadaNetwork, error)
	ListACLs(ctx context.Context, opts service.OmadaOptions) ([]service.OmadaACLRule, error)
	ListClients(ctx context.Context, opts service.OmadaOptions) ([]service.OmadaClient, error)
	Import(ctx context.Context, opts service.OmadaOptions) (*service.OmadaImport, error)
	Plan(ctx context.Context, opts service.OmadaOptions, proposedYAML string) (*service.OmadaPlan, error)
	ApplyACL(ctx context.Context, opts service.OmadaOptions, req service.OmadaACLApplyRequest) (*service.OmadaACLApplyResult, error)
}

// opnsenseSurface is the OPNsense observation surface exposed to agents.
type opnsenseSurface interface {
	Info(ctx context.Context, opts service.OpnsenseOptions) (*service.OpnsenseInfo, error)
	ListInterfaces(ctx context.Context, opts service.OpnsenseOptions) ([]service.OpnsenseInterface, error)
	ListFirewallRules(ctx context.Context, opts service.OpnsenseOptions) ([]service.OpnsenseFirewallRule, error)
	ListClients(ctx context.Context, opts service.OpnsenseOptions) ([]service.OpnsenseClient, error)
}

// Server is the MCP stdio server
type Server struct {
	reader      io.Reader
	writer      io.Writer
	initialized bool
	checkSvc    *service.CheckService
	omadaSvc    omadaSurface
	opnsenseSvc opnsenseSurface
}

// NewServer creates a new MCP server
func NewServer() *Server {
	return &Server{
		reader:      os.Stdin,
		writer:      os.Stdout,
		checkSvc:    service.NewCheckService(),
		omadaSvc:    service.NewOmadaService(),
		opnsenseSvc: service.NewOpnsenseService(),
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
			// Handle notifications (e.g., notifications/initialized)
			if req.Method == "notifications/initialized" {
				continue
			}
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
	s.initialized = true
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
	if !s.initialized {
		return &jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &rpcError{Code: -32002, Message: "server not initialized"},
		}
	}
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
			Description: "Check nyx environment health. Optionally validate a spec file and probe SSH reachability/auth for declared probes.",
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
		{
			Name:        "omada_get_info",
			Description: "Fetch metadata (version, API version, omada CID) from an Omada SDN controller without authentication.",
			InputSchema: inputSchema{
				Type: "object",
				Properties: map[string]propSchema{
					"host":            {Type: "string", Description: "Omada controller hostname or IP"},
					"skip_tls_verify": {Type: "boolean", Description: "Skip TLS certificate verification (self-signed certs)"},
					"ca_cert_path":    {Type: "string", Description: "Path to a CA certificate for the controller"},
				},
				Required: []string{"host"},
			},
		},
		{
			Name:        "omada_list_networks",
			Description: "List LAN networks/VLANs configured on an Omada SDN controller site.",
			InputSchema: inputSchema{
				Type: "object",
				Properties: map[string]propSchema{
					"host":            {Type: "string", Description: "Omada controller hostname or IP"},
					"username":        {Type: "string", Description: "Omada account username"},
					"password":        {Type: "string", Description: "Omada account password"},
					"site":            {Type: "string", Description: "Optional site name; defaults to the first site"},
					"skip_tls_verify": {Type: "boolean", Description: "Skip TLS certificate verification (self-signed certs)"},
					"ca_cert_path":    {Type: "string", Description: "Path to a CA certificate for the controller"},
				},
				Required: []string{"host", "username", "password"},
			},
		},
		{
			Name:        "omada_list_acls",
			Description: "List ACL (firewall) rules, including gateway ACLs, on an Omada SDN controller site.",
			InputSchema: inputSchema{
				Type: "object",
				Properties: map[string]propSchema{
					"host":            {Type: "string", Description: "Omada controller hostname or IP"},
					"username":        {Type: "string", Description: "Omada account username"},
					"password":        {Type: "string", Description: "Omada account password"},
					"site":            {Type: "string", Description: "Optional site name; defaults to the first site"},
					"skip_tls_verify": {Type: "boolean", Description: "Skip TLS certificate verification (self-signed certs)"},
					"ca_cert_path":    {Type: "string", Description: "Path to a CA certificate for the controller"},
				},
				Required: []string{"host", "username", "password"},
			},
		},
		{
			Name:        "omada_list_clients",
			Description: "List currently connected clients on an Omada SDN controller site.",
			InputSchema: inputSchema{
				Type: "object",
				Properties: map[string]propSchema{
					"host":            {Type: "string", Description: "Omada controller hostname or IP"},
					"username":        {Type: "string", Description: "Omada account username"},
					"password":        {Type: "string", Description: "Omada account password"},
					"site":            {Type: "string", Description: "Optional site name; defaults to the first site"},
					"skip_tls_verify": {Type: "boolean", Description: "Skip TLS certificate verification (self-signed certs)"},
					"ca_cert_path":    {Type: "string", Description: "Path to a CA certificate for the controller"},
				},
				Required: []string{"host", "username", "password"},
			},
		},
		{
			Name:        "omada_import",
			Description: "Import the Omada controller state into an intent spec (networks, policies, assertions) for the selected site.",
			InputSchema: inputSchema{
				Type: "object",
				Properties: map[string]propSchema{
					"host":            {Type: "string", Description: "Omada controller hostname or IP"},
					"username":        {Type: "string", Description: "Omada account username"},
					"password":        {Type: "string", Description: "Omada account password"},
					"site":            {Type: "string", Description: "Optional site name; defaults to the first site"},
					"skip_tls_verify": {Type: "boolean", Description: "Skip TLS certificate verification (self-signed certs)"},
					"ca_cert_path":    {Type: "string", Description: "Path to a CA certificate for the controller"},
				},
				Required: []string{"host", "username", "password"},
			},
		},
		{
			Name:        "omada_plan",
			Description: "Preview the difference between the controller's current ACL rules and a proposed intent spec. Read-only: nothing is applied.",
			InputSchema: inputSchema{
				Type: "object",
				Properties: map[string]propSchema{
					"host":            {Type: "string", Description: "Omada controller hostname or IP"},
					"username":        {Type: "string", Description: "Omada account username"},
					"password":        {Type: "string", Description: "Omada account password"},
					"site":            {Type: "string", Description: "Optional site name; defaults to the first site"},
					"skip_tls_verify": {Type: "boolean", Description: "Skip TLS certificate verification (self-signed certs)"},
					"ca_cert_path":    {Type: "string", Description: "Path to a CA certificate for the controller"},
					"spec":            {Type: "string", Description: "Proposed intent spec (YAML): networks and policies to preview"},
				},
				Required: []string{"host", "username", "password", "spec"},
			},
		},
		{
			Name:        "omada_apply_acl",
			Description: "Apply an ACL policy change on the controller: create the rule or enable a disabled matching rule. Dry-run is the default: set dry_run=false to apply for real. A real apply is followed by a targeted isolation audit of the changed endpoints (disable with post_audit=false).",
			InputSchema: inputSchema{
				Type: "object",
				Properties: map[string]propSchema{
					"host":            {Type: "string", Description: "Omada controller hostname or IP"},
					"username":        {Type: "string", Description: "Omada account username"},
					"password":        {Type: "string", Description: "Omada account password"},
					"site":            {Type: "string", Description: "Optional site name; defaults to the first site"},
					"skip_tls_verify": {Type: "boolean", Description: "Skip TLS certificate verification (self-signed certs)"},
					"ca_cert_path":    {Type: "string", Description: "Path to a CA certificate for the controller"},
					"from":            {Type: "string", Description: "Source network name"},
					"to":              {Type: "string", Description: "Destination network name"},
					"action":          {Type: "string", Description: "Policy action: allow or deny"},
					"policy_name":     {Type: "string", Description: "Optional rule name; a from-to-action name is derived when empty"},
					"dry_run":         {Type: "boolean", Description: "Preview only. Default true — set false to apply for real."},
					"post_audit":      {Type: "boolean", Description: "Run a targeted isolation audit after a real apply. Default true."},
				},
				Required: []string{"host", "username", "password", "from", "to", "action"},
			},
		},
		{
			Name:        "opnsense_get_info",
			Description: "Fetch firmware metadata (version, product, arch) from an OPNsense firewall.",
			InputSchema: inputSchema{
				Type: "object",
				Properties: map[string]propSchema{
					"host":            {Type: "string", Description: "OPNsense firewall hostname or IP"},
					"api_key":         {Type: "string", Description: "OPNsense API key"},
					"api_secret":      {Type: "string", Description: "OPNsense API secret"},
					"skip_tls_verify": {Type: "boolean", Description: "Skip TLS certificate verification (self-signed certs)"},
					"ca_cert_path":    {Type: "string", Description: "Path to a CA certificate for the firewall"},
				},
				Required: []string{"host", "api_key", "api_secret"},
			},
		},
		{
			Name:        "opnsense_list_interfaces",
			Description: "List OPNsense interfaces with their IP configuration.",
			InputSchema: inputSchema{
				Type: "object",
				Properties: map[string]propSchema{
					"host":            {Type: "string", Description: "OPNsense firewall hostname or IP"},
					"api_key":         {Type: "string", Description: "OPNsense API key"},
					"api_secret":      {Type: "string", Description: "OPNsense API secret"},
					"skip_tls_verify": {Type: "boolean", Description: "Skip TLS certificate verification (self-signed certs)"},
					"ca_cert_path":    {Type: "string", Description: "Path to a CA certificate for the firewall"},
				},
				Required: []string{"host", "api_key", "api_secret"},
			},
		},
		{
			Name:        "opnsense_list_firewall_rules",
			Description: "List OPNsense firewall filter rules (actions pass/block/reject).",
			InputSchema: inputSchema{
				Type: "object",
				Properties: map[string]propSchema{
					"host":            {Type: "string", Description: "OPNsense firewall hostname or IP"},
					"api_key":         {Type: "string", Description: "OPNsense API key"},
					"api_secret":      {Type: "string", Description: "OPNsense API secret"},
					"skip_tls_verify": {Type: "boolean", Description: "Skip TLS certificate verification (self-signed certs)"},
					"ca_cert_path":    {Type: "string", Description: "Path to a CA certificate for the firewall"},
				},
				Required: []string{"host", "api_key", "api_secret"},
			},
		},
		{
			Name:        "opnsense_list_clients",
			Description: "List OPNsense DHCP leases as the host inventory (OPNsense exposes no live client state).",
			InputSchema: inputSchema{
				Type: "object",
				Properties: map[string]propSchema{
					"host":            {Type: "string", Description: "OPNsense firewall hostname or IP"},
					"api_key":         {Type: "string", Description: "OPNsense API key"},
					"api_secret":      {Type: "string", Description: "OPNsense API secret"},
					"skip_tls_verify": {Type: "boolean", Description: "Skip TLS certificate verification (self-signed certs)"},
					"ca_cert_path":    {Type: "string", Description: "Path to a CA certificate for the firewall"},
				},
				Required: []string{"host", "api_key", "api_secret"},
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
	if !s.initialized {
		return &jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &rpcError{Code: -32002, Message: "server not initialized"},
		}
	}
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
		result := s.checkSvc.CheckRoute(ctx, target)
		result.Finish()
		if result.Status == models.StatusError {
			return toJSON(result), true
		}
		return toJSON(result), false

	case "check_vpn":
		target, _ := args["target"].(string)
		if target == "" {
			return "target parameter is required", true
		}
		result := s.checkSvc.CheckVPN(ctx, target)
		result.Finish()
		if result.Status == models.StatusError {
			return toJSON(result), true
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
					Type:   "isolation",
					From:   from,
					To:     to,
					Expect: expectDeny,
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
		ifaces, err := s.checkSvc.GetInterfaces(ctx)
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

		nmapResult := service.NmapCheck()
		if !nmap.Available() {
			nmapResult.Status = models.StatusFail
			nmapResult.Summary = "nmap is not installed or not in PATH"
		}
		findings = append(findings, *nmapResult)

		if specPath != "" {
			findings = append(findings, *service.SpecFileCheck(specPath))
			findings = append(findings, *service.SpecValidCheck(specPath))
			for _, c := range service.ProbeChecks(specPath) {
				findings = append(findings, *c)
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

	case "omada_get_info":
		opts, msg := omadaOptionsFromArgs(args, false)
		if msg != "" {
			return msg, true
		}
		info, err := s.omadaSvc.Info(ctx, opts)
		if err != nil {
			return fmt.Sprintf("omada info request failed: %v", err), true
		}
		return toJSON(info), false

	case "omada_list_networks":
		opts, msg := omadaOptionsFromArgs(args, true)
		if msg != "" {
			return msg, true
		}
		nets, err := s.omadaSvc.ListNetworks(ctx, opts)
		if err != nil {
			return fmt.Sprintf("omada networks request failed: %v", err), true
		}
		return toJSON(nets), false

	case "omada_list_acls":
		opts, msg := omadaOptionsFromArgs(args, true)
		if msg != "" {
			return msg, true
		}
		rules, err := s.omadaSvc.ListACLs(ctx, opts)
		if err != nil {
			return fmt.Sprintf("omada acls request failed: %v", err), true
		}
		return toJSON(rules), false

	case "omada_list_clients":
		opts, msg := omadaOptionsFromArgs(args, true)
		if msg != "" {
			return msg, true
		}
		clients, err := s.omadaSvc.ListClients(ctx, opts)
		if err != nil {
			return fmt.Sprintf("omada clients request failed: %v", err), true
		}
		return toJSON(clients), false

	case "omada_import":
		opts, msg := omadaOptionsFromArgs(args, true)
		if msg != "" {
			return msg, true
		}
		imp, err := s.omadaSvc.Import(ctx, opts)
		if err != nil {
			return fmt.Sprintf("omada import request failed: %v", err), true
		}
		return toJSON(imp), false

	case "omada_plan":
		opts, msg := omadaOptionsFromArgs(args, true)
		if msg != "" {
			return msg, true
		}
		specYAML, _ := args["spec"].(string)
		if specYAML == "" {
			return "spec parameter is required", true
		}
		plan, err := s.omadaSvc.Plan(ctx, opts, specYAML)
		if err != nil {
			return fmt.Sprintf("omada plan request failed: %v", err), true
		}
		return toJSON(plan), false

	case "omada_apply_acl":
		opts, msg := omadaOptionsFromArgs(args, true)
		if msg != "" {
			return msg, true
		}
		req := service.OmadaACLApplyRequest{
			PolicyName: argString(args, "policy_name"),
			From:       argString(args, "from"),
			To:         argString(args, "to"),
			Action:     argString(args, "action"),
			DryRun:     argBoolDefault(args, "dry_run", true),
			PostAudit:  argBoolDefault(args, "post_audit", true),
		}
		if req.From == "" {
			return "from parameter is required", true
		}
		if req.To == "" {
			return "to parameter is required", true
		}
		if req.Action == "" {
			return "action parameter is required", true
		}
		res, err := s.omadaSvc.ApplyACL(ctx, opts, req)
		if err != nil {
			return fmt.Sprintf("omada apply request failed: %v", err), true
		}
		return toJSON(res), false

	case "opnsense_get_info":
		opts, msg := opnsenseOptionsFromArgs(args, true)
		if msg != "" {
			return msg, true
		}
		info, err := s.opnsenseSvc.Info(ctx, opts)
		if err != nil {
			return fmt.Sprintf("opnsense info request failed: %v", err), true
		}
		return toJSON(info), false

	case "opnsense_list_interfaces":
		opts, msg := opnsenseOptionsFromArgs(args, true)
		if msg != "" {
			return msg, true
		}
		ifaces, err := s.opnsenseSvc.ListInterfaces(ctx, opts)
		if err != nil {
			return fmt.Sprintf("opnsense interfaces request failed: %v", err), true
		}
		return toJSON(ifaces), false

	case "opnsense_list_firewall_rules":
		opts, msg := opnsenseOptionsFromArgs(args, true)
		if msg != "" {
			return msg, true
		}
		rules, err := s.opnsenseSvc.ListFirewallRules(ctx, opts)
		if err != nil {
			return fmt.Sprintf("opnsense firewall rules request failed: %v", err), true
		}
		return toJSON(rules), false

	case "opnsense_list_clients":
		opts, msg := opnsenseOptionsFromArgs(args, true)
		if msg != "" {
			return msg, true
		}
		clients, err := s.opnsenseSvc.ListClients(ctx, opts)
		if err != nil {
			return fmt.Sprintf("opnsense clients request failed: %v", err), true
		}
		return toJSON(clients), false

	default:
		return fmt.Sprintf("unknown tool: %s", name), true
	}
}

// omadaOptionsFromArgs extracts Omada connection options from tool arguments.
// The returned message is non-empty when a required parameter is missing.
func omadaOptionsFromArgs(args map[string]interface{}, needCredentials bool) (service.OmadaOptions, string) {
	var opts service.OmadaOptions
	opts.Host, _ = args["host"].(string)
	if opts.Host == "" {
		return opts, "host parameter is required"
	}
	if needCredentials {
		opts.Username, _ = args["username"].(string)
		opts.Password, _ = args["password"].(string)
		if opts.Username == "" || opts.Password == "" {
			return opts, "username and password parameters are required"
		}
	}
	opts.Site, _ = args["site"].(string)
	opts.SkipTLSVerify, _ = args["skip_tls_verify"].(bool)
	opts.CACertPath, _ = args["ca_cert_path"].(string)
	return opts, ""
}

// argString returns a string tool argument, or "" when absent.
func argString(args map[string]interface{}, key string) string {
	s, _ := args[key].(string)
	return s
}

// argBoolDefault returns a boolean tool argument, or the default when absent.
func argBoolDefault(args map[string]interface{}, key string, def bool) bool {
	v, ok := args[key].(bool)
	if !ok {
		return def
	}
	return v
}

// opnsenseOptionsFromArgs extracts OPNsense connection options from tool
// arguments. The returned message is non-empty when a required parameter is
// missing.
func opnsenseOptionsFromArgs(args map[string]interface{}, needCredentials bool) (service.OpnsenseOptions, string) {
	var opts service.OpnsenseOptions
	opts.Host, _ = args["host"].(string)
	if opts.Host == "" {
		return opts, "host parameter is required"
	}
	if needCredentials {
		opts.APIKey, _ = args["api_key"].(string)
		opts.APISecret, _ = args["api_secret"].(string)
		if opts.APIKey == "" || opts.APISecret == "" {
			return opts, "api key and api secret parameters are required"
		}
	}
	opts.SkipTLSVerify, _ = args["skip_tls_verify"].(bool)
	opts.CACertPath, _ = args["ca_cert_path"].(string)
	return opts, ""
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
