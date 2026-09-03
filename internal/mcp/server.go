// Package mcp implements the Model Context Protocol (MCP) stdio server for exposing nyx capabilities to AI agents.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jpvelasco/nyx/internal/audit"
	"github.com/jpvelasco/nyx/internal/credentials"
	"github.com/jpvelasco/nyx/internal/credentials/credmanager"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/logger"
	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/jpvelasco/nyx/internal/storepath"
	"github.com/jpvelasco/nyx/internal/version"
)

const (
	// maxFrameSize caps a single newline-delimited JSON-RPC frame. Frames
	// beyond this size are answered with a parse error and discarded so an
	// oversized message cannot crash or wedge the server.
	maxFrameSize = 8 * 1024 * 1024
)

// toolCallTimeout bounds a single tools/call dispatch so a hung backend
// cannot leave the server wedged. Dispatch runs in a goroutine and the
// caller selects on the result, so the server always answers within this
// window even if the backend ignores context cancellation.
var toolCallTimeout = 5 * time.Minute

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
	Inventory(ctx context.Context, opts service.OmadaOptions) (*service.OmadaInventory, error)
	Import(ctx context.Context, opts service.OmadaOptions) (*service.OmadaImport, error)
	Plan(ctx context.Context, opts service.OmadaOptions, proposedYAML string) (*service.OmadaPlan, error)
	ApplyACL(ctx context.Context, opts service.OmadaOptions, req service.OmadaACLApplyRequest) (*service.OmadaACLApplyResult, error)
	ListPortForwardings(ctx context.Context, opts service.OmadaOptions) ([]service.OmadaPortForwarding, error)
	ListOneToOneNAT(ctx context.Context, opts service.OmadaOptions) ([]service.OmadaOneToOneNAT, error)
	GetALGSettings(ctx context.Context, opts service.OmadaOptions) (*service.OmadaALGSettings, error)
	GetFirewallSettings(ctx context.Context, opts service.OmadaOptions) (*service.OmadaFirewallSettings, error)
	NatFacts(ctx context.Context, opts service.OmadaOptions) (*service.OmadaNatFacts, error)
	GetUplinkInfo(ctx context.Context, opts service.OmadaOptions, macs []string) ([]service.OmadaUplinkInfo, error)
	ListSwitchPorts(ctx context.Context, opts service.OmadaOptions, switchMAC string) ([]service.OmadaSwitchPort, error)
	ListLanProfiles(ctx context.Context, opts service.OmadaOptions) ([]service.OmadaLanProfile, error)
	PlanPort(ctx context.Context, opts service.OmadaOptions, req service.OmadaPortProfileRequest) (*service.OmadaPortPlan, error)
	ApplyPortProfile(ctx context.Context, opts service.OmadaOptions, req service.OmadaPortProfileRequest, dryRun bool) (*service.OmadaPortProfileApplyResult, error)
}

// opnsenseSurface is the OPNsense observation surface exposed to agents.
type opnsenseSurface interface {
	Info(ctx context.Context, opts service.OpnsenseOptions) (*service.OpnsenseInfo, error)
	ListInterfaces(ctx context.Context, opts service.OpnsenseOptions) ([]service.OpnsenseInterface, error)
	ListFirewallRules(ctx context.Context, opts service.OpnsenseOptions) ([]service.OpnsenseFirewallRule, error)
	ListClients(ctx context.Context, opts service.OpnsenseOptions) ([]service.OpnsenseClient, error)
	ListPortForwardRules(ctx context.Context, opts service.OpnsenseOptions) ([]service.OpnsenseNatRule, error)
	ListOneToOneRules(ctx context.Context, opts service.OpnsenseOptions) ([]service.OpnsenseNatRule, error)
	ListSourceNatRules(ctx context.Context, opts service.OpnsenseOptions) ([]service.OpnsenseNatRule, error)
	ListAliases(ctx context.Context, opts service.OpnsenseOptions) ([]service.OpnsenseAlias, error)
	GetOutboundNatMode(ctx context.Context, opts service.OpnsenseOptions) (string, error)
	GetNAT(ctx context.Context, opts service.OpnsenseOptions) (*service.OpnsenseNatSummary, error)
	Inventory(ctx context.Context, opts service.OpnsenseOptions) (*service.OpnsenseInventory, error)
	PlanNat(ctx context.Context, opts service.OpnsenseOptions, req service.OpnsenseNatApplyRequest) (*providers.NatPlan, error)
	ApplyNat(ctx context.Context, opts service.OpnsenseOptions, req service.OpnsenseNatApplyRequest) (*providers.NatApplyResult, error)
}

// topologySurface is the cross-provider topology assessment exposed to
// agents: per-provider NAT posture plus the double-NAT risk verdict.
type topologySurface interface {
	Report(ctx context.Context, opts service.TopologyOptions) (*service.TopologyReport, error)
}

// Server is the MCP stdio server
type Server struct {
	reader      io.Reader
	writer      io.Writer
	initialized bool
	checkSvc    *service.CheckService
	omadaSvc    omadaSurface
	opnsenseSvc opnsenseSurface
	topoSvc     topologySurface
	// logger writes MCP operation records to the shared rotating log file.
	// The writer is the stdout RPC channel, so nothing is ever logged to
	// it; a nil logger disables file logging (tests).
	logger *slog.Logger
	// credEnv reads the Omada credential env vars (keys OMADA_HOST /
	// OMADA_CLIENT_ID / OMADA_CLIENT_SECRET / OMADA_SITE) and opnsenseCredEnv
	// the OPNsense ones (OPNSENSE_HOST / OPNSENSE_API_KEY /
	// OPNSENSE_API_SECRET). A missing key leaves that layer empty.
	credEnv         map[string]func(string) string
	opnsenseCredEnv map[string]func(string) string
}

// NewServer creates a new MCP server. slog.Default() is the CLI's shared
// OTel-backed pipeline (wired in cli init), so MCP tool calls land in the
// same audit file as CLI commands; when no pipeline is wired (tests) the
// stderr default keeps records visible.
func NewServer() *Server {
	return NewServerWithLogger(slog.Default())
}

// NewServerWithLogger creates an MCP server that writes operation records
// through sl.
func NewServerWithLogger(sl *slog.Logger) *Server {
	omadaSvc := service.NewOmadaService()
	omadaSvc.PostAudit = func(ctx context.Context, spec *intent.Spec) (*models.AuditReport, error) {
		return audit.NewEngine(spec).Run(ctx)
	}
	return &Server{
		reader:          os.Stdin,
		writer:          os.Stdout,
		checkSvc:        service.NewCheckService(),
		omadaSvc:        omadaSvc,
		opnsenseSvc:     service.NewOpnsenseService(),
		topoSvc:         service.NewTopologyService(),
		logger:          sl,
		credEnv:         credEnvFrom(OmadaCredEnvVars),
		opnsenseCredEnv: credEnvFrom(OpnsenseCredEnvVars),
	}
}

// Serve runs the MCP server loop on stdio
func (s *Server) Serve(ctx context.Context) error {
	reader := bufio.NewReaderSize(s.reader, 64*1024)

	for {
		frame, err := readFrame(reader)
		if err == io.EOF {
			if len(frame) == 0 {
				return nil
			}
			err = nil // process the final frame that has no trailing newline
		}
		if err != nil {
			if err == errFrameTooLarge {
				s.writeResponse(&jsonRPCResponse{
					JSONRPC: "2.0",
					Error:   &rpcError{Code: -32700, Message: "parse error: frame exceeds the size limit"},
				})
				continue
			}
			return err
		}

		frame = bytes.TrimSpace(frame)
		if len(frame) == 0 {
			continue
		}

		var req jsonRPCRequest
		if err := json.Unmarshal(frame, &req); err != nil {
			s.writeResponse(&jsonRPCResponse{
				JSONRPC: "2.0",
				Error:   &rpcError{Code: -32700, Message: "parse error: invalid JSON-RPC message"},
			})
			continue
		}

		// Notifications have no ID and need no response
		if req.ID == nil || string(req.ID) == "null" {
			continue
		}

		s.writeResponse(s.handleRequest(ctx, &req))
	}
}

// errFrameTooLarge marks a newline-delimited frame that exceeds maxFrameSize.
var errFrameTooLarge = errors.New("frame too large")

// readFrame reads one newline-delimited frame, capping its size so a single
// oversized line cannot exhaust memory. The remainder of an oversized line is
// drained so the server can keep serving subsequent frames. A final frame
// without a trailing newline is returned together with io.EOF.
func readFrame(r *bufio.Reader) ([]byte, error) {
	var frame []byte
	for {
		chunk, err := r.ReadSlice('\n')
		frame = append(frame, chunk...)
		if err == bufio.ErrBufferFull {
			if len(frame) > maxFrameSize {
				if drainErr := drainLine(r); drainErr != nil {
					return nil, drainErr
				}
				return nil, errFrameTooLarge
			}
			continue
		}
		if len(frame) > maxFrameSize {
			return nil, errFrameTooLarge
		}
		return frame, err // nil or io.EOF
	}
}

// drainLine discards the remainder of a line that exceeded maxFrameSize.
func drainLine(r *bufio.Reader) error {
	for {
		_, err := r.ReadSlice('\n')
		if err == bufio.ErrBufferFull {
			continue
		}
		return err // nil or io.EOF — either way the line has ended
	}
}

func (s *Server) writeResponse(resp *jsonRPCResponse) {
	respBytes, err := json.Marshal(resp)
	if err != nil {
		return
	}
	fmt.Fprintf(s.writer, "%s\n", respBytes)
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
			InputSchema: omadaToolSchema(),
		},
		{
			Name:        "omada_list_acls",
			Description: "List ACL (firewall) rules, including gateway ACLs, on an Omada SDN controller site.",
			InputSchema: omadaToolSchema(),
		},
		{
			Name:        "omada_list_clients",
			Description: "List currently connected clients on an Omada SDN controller site.",
			InputSchema: omadaToolSchema(),
		},
		{
			Name:        "omada_inventory",
			Description: "Observe the Omada site point-in-time: managed devices (with firmware + upgrade flags), LAN networks with their gateway bindings, both ACL scopes and their rule counts, and the active client count. Read-only.",
			InputSchema: omadaToolSchema(),
		},
		{
			Name:        "omada_import",
			Description: "Import the Omada controller state into an intent spec (networks, policies, assertions) for the selected site.",
			InputSchema: omadaToolSchema(),
		},
		{
			Name:        "omada_plan",
			Description: "Preview the difference between the controller's current ACL rules and a proposed intent spec. Read-only: nothing is applied.",
			InputSchema: omadaToolSchemaExtra(map[string]propSchema{
				"spec": {Type: "string", Description: "Proposed intent spec (YAML): networks and policies to preview"},
			}, []string{"host", "spec"}),
		},
		{
			Name:        "omada_apply_acl",
			Description: "Apply an ACL policy change on the controller: create the rule or enable a disabled matching rule, across every from-to pair. Dry-run is the default: set dry_run=false to apply for real. A real apply is followed by a targeted isolation audit of the changed endpoints (disable with post_audit=false).",
			InputSchema: omadaToolSchemaExtra(map[string]propSchema{
				"from":        {Type: "string", Description: "Source network name(s), comma-separated for one-to-many or many-to-many"},
				"to":          {Type: "string", Description: "Destination network name(s), comma-separated for one-to-many or many-to-many"},
				"action":      {Type: "string", Description: "Policy action: allow or deny"},
				"policy_name": {Type: "string", Description: "Optional rule name; a from-to-action name is derived when empty"},
				"scope":       {Type: "string", Description: "ACL scope: switch (default) or gateway. eap is not supported."},
				"protocols":   {Type: "string", Description: "Optional comma-separated IP protocol numbers (e.g. 6,17). Empty means all protocols."},
				"dry_run":     {Type: "boolean", Description: "Preview only. Default true — set false to apply for real."},
				"post_audit":  {Type: "boolean", Description: "Run a targeted isolation audit after a real apply. Default true."},
			}, []string{"host", "from", "to", "action"}),
		},
		{
			Name:        "omada_list_port_forwardings",
			Description: "List the Omada gateway's NAT port-forwarding rules for a site.",
			InputSchema: omadaToolSchema(),
		},
		{
			Name:        "omada_list_one_to_one_nat",
			Description: "List the Omada gateway's one-to-one NAT rules for a site.",
			InputSchema: omadaToolSchema(),
		},
		{
			Name:        "omada_get_nat_settings",
			Description: "Read the Omada gateway's NAT application-layer gateways (ALG) and firewall session-timeout settings for a site.",
			InputSchema: omadaToolSchema(),
		},
		{
			Name:        "omada_nat_facts",
			Description: "Observe the Omada site's NAT posture in one call: port-forward and one-to-one rule counts, ALG and firewall settings, and whether a managed gateway is present. Read-only input to the topology report.",
			InputSchema: omadaToolSchema(),
		},
		{
			Name:        "omada_get_uplink_info",
			Description: "Look up which managed device (and which port) a device MAC is cabled into, from the controller's uplink observation. Use to find where a standalone switch's uplink lands before changing port profiles. Read-only.",
			InputSchema: omadaToolSchemaExtra(map[string]propSchema{
				"device_mac": {Type: "string", Description: "MAC address of the device to look up (e.g. the standalone switch's MAC)"},
			}, []string{"host", "device_mac"}),
		},
		{
			Name:        "omada_list_switch_ports",
			Description: "List switch ports with their live VLAN membership: the bound profile plus the resolved native (untagged) network and tagged set. Read-only.",
			InputSchema: omadaToolSchemaExtra(map[string]propSchema{
				"switch_mac": {Type: "string", Description: "Optional switch MAC to filter ports; empty lists every switch in the site"},
			}, []string{"host"}),
		},
		{
			Name:        "omada_list_lan_profiles",
			Description: "List the site's LAN profiles — the VLAN membership sets ports can be bound to: the native (untagged) network plus the tagged set per profile. Read-only.",
			InputSchema: omadaToolSchema(),
		},
		{
			Name:        "omada_plan_port",
			Description: "Preview bringing one switch port to a desired VLAN membership (native network plus tagged set): the port's current membership and profile, and whether an existing LAN profile can be rebound or a new one must be created. Read-only: nothing is applied.",
			InputSchema: omadaToolSchemaExtra(map[string]propSchema{
				"switch_mac":   {Type: "string", Description: "Switch MAC hosting the port"},
				"port":         {Type: "integer", Description: "Port number (1-based)"},
				"native":       {Type: "string", Description: "Native (untagged) LAN network name"},
				"tagged":       {Type: "string", Description: "Optional comma-separated tagged LAN network names"},
				"profile_name": {Type: "string", Description: "Optional name for a new profile; derived when empty"},
			}, []string{"host", "switch_mac", "port", "native"}),
		},
		{
			Name:        "omada_apply_port_profile",
			Description: "Bind a switch port to a LAN profile with the desired VLAN membership (native network plus tagged set): find an existing profile whose membership matches, create one when none does, then bind it to the port. Idempotent (unchanged / bound / created_and_bound). Dry-run is the default: set dry_run=false to apply for real. The result carries before/after evidence (the port row joined to its referenced profile).",
			InputSchema: omadaToolSchemaExtra(map[string]propSchema{
				"switch_mac":   {Type: "string", Description: "Switch MAC hosting the port"},
				"port":         {Type: "integer", Description: "Port number (1-based)"},
				"native":       {Type: "string", Description: "Native (untagged) LAN network name"},
				"tagged":       {Type: "string", Description: "Optional comma-separated tagged LAN network names"},
				"profile_name": {Type: "string", Description: "Optional name for a new profile; derived when empty"},
				"dry_run":      {Type: "boolean", Description: "Preview only. Default true — set false to apply for real."},
			}, []string{"host", "switch_mac", "port", "native"}),
		},
		{
			Name:        "opnsense_get_info",
			Description: "Fetch system metadata (version, product, arch) from an OPNsense firewall. Reads the Dashboard-privileged system-information endpoint (no System: Firmware privilege required).",
			InputSchema: opnsenseToolSchema(),
		},
		{
			Name:        "opnsense_list_interfaces",
			Description: "List OPNsense interfaces with their IP configuration.",
			InputSchema: opnsenseToolSchema(),
		},
		{
			Name:        "opnsense_list_firewall_rules",
			Description: "List OPNsense firewall filter rules (actions pass/block/reject).",
			InputSchema: opnsenseToolSchema(),
		},
		{
			Name:        "opnsense_list_clients",
			Description: "List OPNsense DHCP leases as the host inventory (OPNsense exposes no live client state).",
			InputSchema: opnsenseToolSchema(),
		},
		{
			Name:        "opnsense_list_port_forward_rules",
			Description: "List OPNsense destination NAT (port forward) rules.",
			InputSchema: opnsenseToolSchema(),
		},
		{
			Name:        "opnsense_list_one_to_one_rules",
			Description: "List OPNsense one-to-one NAT rules.",
			InputSchema: opnsenseToolSchema(),
		},
		{
			Name:        "opnsense_list_source_nat_rules",
			Description: "List OPNsense source NAT rules, including the generic outbound-NAT row.",
			InputSchema: opnsenseToolSchema(),
		},
		{
			Name:        "opnsense_list_aliases",
			Description: "List OPNsense firewall address aliases.",
			InputSchema: opnsenseToolSchema(),
		},
		{
			Name:        "opnsense_get_nat",
			Description: "Read the OPNsense NAT posture in one call: outbound (source) NAT mode plus every NAT rule set. The outbound mode is the key double-NAT signal — a transparent proxy reports 'disabled'.",
			InputSchema: opnsenseToolSchema(),
		},
		{
			Name:        "opnsense_inventory",
			Description: "Observe the OPNsense firewall point-in-time: system metadata, its interfaces as networks with gateway bindings, the firewall rule count, and the active client (DHCP lease) count. Read-only.",
			InputSchema: opnsenseToolSchema(),
		},
		{
			Name:        "opnsense_plan_nat",
			Description: "Preview an OPNsense NAT mutation (port-forward, one-to-one, or source-NAT create/update/delete/toggle). Dry-run by default: issues zero POSTs. The result states the exact API endpoint(s), the current collection state, the double-NAT guard verdict, and that staged changes are not in the dataplane until the controller applies them.",
			InputSchema: opnsenseNatToolSchema(),
		},
		{
			Name:        "opnsense_apply_nat",
			Description: "Apply an OPNsense NAT mutation (port-forward, one-to-one, or source-NAT create/update/delete/toggle). Dry-run by default: set dry_run=false to apply for real. A real apply stages changes to config.xml — they are not in the dataplane until the controller applies them (S3.9, follow-up). The result carries before/after evidence and the exact API endpoint(s) touched.",
			InputSchema: opnsenseNatToolSchema(),
		},
		{
			Name:        "topology",
			Description: "Assess the network topology from both providers' NAT posture: per-device NAT role and a site-level double-NAT risk verdict. Configure credentials for omada and/or opnsense (parameters, env vars, or the credential store) to observe that provider; omit a provider's host to skip it.",
			InputSchema: inputSchema{
				Type: "object",
				Properties: map[string]propSchema{
					"omada_host":               {Type: "string", Description: "Omada controller hostname or IP (omit to skip Omada)"},
					"omada_client_id":          {Type: "string", Description: "Omada Open API client ID"},
					"omada_client_secret":      {Type: "string", Description: "Omada Open API client secret"},
					"omada_site":               {Type: "string", Description: "Optional Omada site name; defaults to the first site"},
					"omada_skip_tls_verify":    {Type: "boolean", Description: "Skip TLS certificate verification for the Omada controller (self-signed certs)"},
					"omada_ca_cert_path":       {Type: "string", Description: "Path to a CA certificate for the Omada controller"},
					"opnsense_host":            {Type: "string", Description: "OPNsense firewall hostname or IP (omit to skip OPNsense)"},
					"opnsense_api_key":         {Type: "string", Description: "OPNsense API key"},
					"opnsense_api_secret":      {Type: "string", Description: "OPNsense API secret"},
					"opnsense_skip_tls_verify": {Type: "boolean", Description: "Skip TLS certificate verification for the firewall (self-signed certs)"},
					"opnsense_ca_cert_path":    {Type: "string", Description: "Path to a CA certificate for the firewall"},
				},
			},
		},
	}

	return &jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  toolsListResult{Tools: tools},
	}
}

// omadaToolSchema returns the credential input schema shared by every
// credential-bearing Omada tool. Required lists only host — client_id /
// client_secret have env and credential-store fallbacks (BDD S3.1), and
// TLS opts are optional.
func omadaToolSchema() inputSchema {
	return inputSchema{
		Type: "object",
		Properties: map[string]propSchema{
			"host":            {Type: "string", Description: "Omada controller hostname or IP"},
			"client_id":       {Type: "string", Description: "Omada Open API client ID"},
			"client_secret":   {Type: "string", Description: "Omada Open API client secret"},
			"site":            {Type: "string", Description: "Optional site name; defaults to the first site"},
			"skip_tls_verify": {Type: "boolean", Description: "Skip TLS certificate verification (self-signed certs)"},
			"ca_cert_path":    {Type: "string", Description: "Path to a CA certificate for the controller"},
		},
		Required: []string{"host"},
	}
}

// omadaToolSchemaExtra returns an Omada credential schema plus extra
// tool-specific properties and a custom required list.
func omadaToolSchemaExtra(extra map[string]propSchema, required []string) inputSchema {
	s := omadaToolSchema()
	for k, v := range extra {
		s.Properties[k] = v
	}
	s.Required = required
	return s
}

// opnsenseToolSchema returns the credential input schema shared by every
// credential-bearing OPNsense tool.
func opnsenseToolSchema() inputSchema {
	return inputSchema{
		Type: "object",
		Properties: map[string]propSchema{
			"host":            {Type: "string", Description: "OPNsense firewall hostname or IP"},
			"api_key":         {Type: "string", Description: "OPNsense API key"},
			"api_secret":      {Type: "string", Description: "OPNsense API secret"},
			"skip_tls_verify": {Type: "boolean", Description: "Skip TLS certificate verification (self-signed certs)"},
			"ca_cert_path":    {Type: "string", Description: "Path to a CA certificate for the firewall"},
		},
		Required: []string{"host"},
	}
}

// opnsenseNatToolSchema returns the OPNsense NAT-mutation tool schema:
// credential fields plus the mutation request shape. Dry-run defaults true;
// a real apply stages changes to config.xml (not the dataplane until the
// controller applies them).
func opnsenseNatToolSchema() inputSchema {
	return opnsenseToolSchemaExtra(map[string]propSchema{
		"operation":        {Type: "string", Description: "NAT collection: port_forward, one_to_one, or source_nat"},
		"action":           {Type: "string", Description: "create (default), update, delete, or toggle. update/delete/toggle require rule_uuid; toggle is port_forward only."},
		"rule_uuid":        {Type: "string", Description: "Target rule UUID for update/delete/toggle"},
		"interfaces":       {Type: "string", Description: "Comma-separated interface names (create/update)"},
		"protocol":         {Type: "string", Description: "IP protocol, lowercase (e.g. tcp, udp); empty = any"},
		"source":           {Type: "string", Description: "Source network / address"},
		"destination":      {Type: "string", Description: "Destination network / address"},
		"port":             {Type: "string", Description: "Destination port (port_forward) or destination port (source_nat)"},
		"local_port":       {Type: "string", Description: "Local (forwarded) port (port_forward)"},
		"target":           {Type: "string", Description: "Target host address (port_forward) or external address (one_to_one)"},
		"type":             {Type: "string", Description: "One-to-one type: binat or nat (one_to_one only)"},
		"label":            {Type: "string", Description: "Rule label / description"},
		"allow_double_nat": {Type: "boolean", Description: "Allow mutations on a bridge/indeterminate device. The flag does NOT override an unknown outbound NAT mode (always refused)."},
		"dry_run":          {Type: "boolean", Description: "Preview only. Default true — set false to apply for real."},
	}, []string{"host", "operation"})
}

// opnsenseToolSchemaExtra returns an OPNsense credential schema plus extra
// tool-specific properties and a custom required list.
func opnsenseToolSchemaExtra(extra map[string]propSchema, required []string) inputSchema {
	s := opnsenseToolSchema()
	for k, v := range extra {
		s.Properties[k] = v
	}
	s.Required = required
	return s
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

	ctx, cancel := context.WithTimeout(ctx, toolCallTimeout)
	defer cancel()

	// Stamp the call with a trace ID so its log records correlate; records
	// go to the shared file, never to the stdout RPC channel.
	traceID := logger.NewTraceID()
	var logCtx *slog.Logger
	if s.logger != nil {
		logCtx = s.logger.With("cmd", "mcp", "tool", params.Name, "trace_id", traceID)
	}

	done := make(chan toolDispatchResult, 1)
	go func() {
		text, isErr := s.dispatchTool(ctx, params.Name, params.Arguments)
		done <- toolDispatchResult{text: text, isErr: isErr}
	}()

	select {
	case result := <-done:
		if logCtx != nil {
			logCtx.Info("tool_call", "error", result.isErr)
		}
		return &jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: toolCallResult{
				Content: []contentBlock{{Type: "text", Text: result.text}},
				IsError: result.isErr,
			},
		}
	case <-ctx.Done():
		if logCtx != nil {
			logCtx.Warn("tool_call_timed_out", "timeout", toolCallTimeout.String())
		}
		return &jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &rpcError{Code: -32000, Message: fmt.Sprintf(
				"tool call %q timed out after %s; the operation was cancelled — check the target network or rerun",
				params.Name, toolCallTimeout)},
		}
	}
}

type toolDispatchResult struct {
	text  string
	isErr bool
}

func okResult(text string) toolDispatchResult {
	return toolDispatchResult{text: text}
}

func errResult(msg string) toolDispatchResult {
	return toolDispatchResult{text: msg, isErr: true}
}

// statusResult finishes a CheckResult and reports it as a tool error only
// when the check itself errored.
func statusResult(result *models.CheckResult) toolDispatchResult {
	result.Finish()
	if result.Status == models.StatusError {
		return errResult(toJSON(result))
	}
	return okResult(toJSON(result))
}

func (s *Server) dispatchTool(ctx context.Context, name string, args map[string]interface{}) (string, bool) {
	handler, ok := toolHandlers[name]
	if !ok {
		return fmt.Sprintf("unknown tool: %s", name), true
	}
	res := handler(s, ctx, args)
	return res.text, res.isErr
}

// requiredHostMsg is the options-builder error for a host that cannot be
// resolved after the args → env → credential-store chain. The topology tool
// treats it as "skip this provider" rather than a failure.
const requiredHostMsg = "host parameter is required"

// omadaOptionsFromArgs extracts Omada connection options from tool arguments,
// falling back to env vars, then the Windows Credential Manager (entry
// nyx-omada-<host>; no-op off Windows), and then the encrypted credential
// store (entry omada/default) for any value left empty — the same
// resolution order as the CLI. The returned message is non-empty when a
// required parameter is missing after all four layers.
func (s *Server) omadaOptionsFromArgs(args map[string]interface{}, needCredentials bool) (service.OmadaOptions, string) {
	var opts service.OmadaOptions
	opts.Host = storepath.FirstNonEmpty(argString(args, "host"), s.env("OMADA_HOST"))
	opts.Site = storepath.FirstNonEmpty(argString(args, "site"), s.env("OMADA_SITE"))
	opts.SkipTLSVerify, _ = args["skip_tls_verify"].(bool)
	opts.CACertPath, _ = args["ca_cert_path"].(string)
	if !needCredentials {
		// Unauthenticated calls (get_info) resolve only host/site from args
		// and env and never touch the store, so they cannot carry
		// credentials.
		if opts.Host == "" {
			return opts, requiredHostMsg
		}
		return opts, ""
	}
	// Credential-bearing calls fill in what args and env left empty from
	// the store (entry omada/default); read failures are silently ignored
	// (credentials.Overlay), leaving the error below for the genuinely
	// unconfigured case. Validation runs after the overlay so a store entry
	// can supply the host too.
	fields := credentials.Fields{
		Host:         opts.Host,
		ClientID:     storepath.FirstNonEmpty(argString(args, "client_id"), s.env("OMADA_CLIENT_ID")),
		ClientSecret: storepath.FirstNonEmpty(argString(args, "client_secret"), s.env("OMADA_CLIENT_SECRET")),
		Site:         opts.Site,
	}
	// Windows Credential Manager layer, between env vars and the store
	// (no-op off Windows — see credmanager).
	fields.ClientID, fields.ClientSecret = credmanager.OverlayOmada(fields.Host, fields.ClientID, fields.ClientSecret)
	credentials.Overlay(storepath.StoreFile(), "omada", "default", &fields)
	opts.Host, opts.ClientID, opts.ClientSecret, opts.Site = fields.Host, fields.ClientID, fields.ClientSecret, fields.Site
	if opts.Host == "" {
		return opts, requiredHostMsg
	}
	if opts.ClientID == "" || opts.ClientSecret == "" {
		return opts, "client_id and client_secret parameters are required: " +
			"set the OMADA_CLIENT_ID / OMADA_CLIENT_SECRET environment variables" +
			credmanager.Hint(opts.Host) + " or run `nyx credentials set omada`"
	}
	return opts, ""
}

// env reads a credential environment variable through the credEnv reader map
// (omada or opnsenseCredEnv depending on the prefix), falling back to the
// real environment when the map is unset (hand-built servers in tests).
func (s *Server) env(name string) string {
	var readers map[string]func(string) string
	switch {
	case strings.HasPrefix(name, "OMADA_"):
		readers = s.credEnv
	case strings.HasPrefix(name, "OPNSENSE_"):
		readers = s.opnsenseCredEnv
	}
	if readers != nil {
		if fn, ok := readers[name]; ok {
			return fn(name)
		}
	}
	return os.Getenv(name)
}

// argString returns a string tool argument, or "" when absent.
func argString(args map[string]interface{}, key string) string {
	s, _ := args[key].(string)
	return s
}

// splitCSV splits a comma-separated list argument, trimming whitespace and
// dropping empty items. An empty or blank argument yields no elements.
func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// parseProtocols parses a comma-separated list of IP protocol numbers. An
// empty string means all protocols and yields nil. The returned message is
// non-empty when a component is not a number.
func parseProtocols(s string) ([]int, string) {
	parts := splitCSV(s)
	if len(parts) == 0 {
		return nil, ""
	}
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, fmt.Sprintf("protocols must be a comma-separated list of protocol numbers, got %q", s)
		}
		out = append(out, n)
	}
	return out, ""
}

// argBoolDefault returns a boolean tool argument, or the default when absent.
func argBoolDefault(args map[string]interface{}, key string, def bool) bool {
	v, ok := args[key].(bool)
	if !ok {
		return def
	}
	return v
}

// argIntDefault returns an integer tool argument (JSON numbers decode as
// float64), or the default when absent or non-numeric.
func argIntDefault(args map[string]interface{}, key string, def int) int {
	if v, ok := args[key].(float64); ok {
		return int(v)
	}
	return def
}

// portProfileRequestFromArgs parses the plan/apply port-profile request
// arguments, shared by omada_plan_port and omada_apply_port_profile.
func portProfileRequestFromArgs(args map[string]interface{}) (service.OmadaPortProfileRequest, string) {
	req := service.OmadaPortProfileRequest{
		SwitchMAC:   argString(args, "switch_mac"),
		Port:        argIntDefault(args, "port", 0),
		Native:      argString(args, "native"),
		Tagged:      splitCSV(argString(args, "tagged")),
		ProfileName: argString(args, "profile_name"),
	}
	if req.SwitchMAC == "" {
		return req, "switch_mac parameter is required"
	}
	if req.Port <= 0 {
		return req, "port parameter is required (1-based port number)"
	}
	if req.Native == "" {
		return req, "native parameter is required"
	}
	return req, ""
}

// opnsenseOptionsFromArgs extracts OPNsense connection options from tool
// arguments, falling back to env vars and then the encrypted credential
// store (entry opnsense/default) for any value left empty — the same
// resolution order as the CLI. The returned message is non-empty when a
// required parameter is missing after all three layers.
func (s *Server) opnsenseOptionsFromArgs(args map[string]interface{}, needCredentials bool) (service.OpnsenseOptions, string) {
	var opts service.OpnsenseOptions
	opts.Host = storepath.FirstNonEmpty(argString(args, "host"), s.env("OPNSENSE_HOST"))
	opts.SkipTLSVerify, _ = args["skip_tls_verify"].(bool)
	opts.CACertPath, _ = args["ca_cert_path"].(string)
	if !needCredentials {
		if opts.Host == "" {
			return opts, "host parameter is required"
		}
		return opts, ""
	}
	// Credential-bearing calls fill in what args and env left empty from
	// the store (entry opnsense/default); read failures are silently
	// ignored (credentials.Overlay). Validation runs after the overlay so a
	// store entry can supply the host too.
	fields := credentials.Fields{
		Host:      opts.Host,
		APIKey:    storepath.FirstNonEmpty(argString(args, "api_key"), s.env("OPNSENSE_API_KEY")),
		APISecret: storepath.FirstNonEmpty(argString(args, "api_secret"), s.env("OPNSENSE_API_SECRET")),
	}
	credentials.Overlay(storepath.StoreFile(), "opnsense", "default", &fields)
	opts.Host, opts.APIKey, opts.APISecret = fields.Host, fields.APIKey, fields.APISecret
	if opts.Host == "" {
		return opts, requiredHostMsg
	}
	if opts.APIKey == "" || opts.APISecret == "" {
		return opts, "api_key and api_secret parameters are required: " +
			"set the OPNSENSE_API_KEY / OPNSENSE_API_SECRET environment variables or run `nyx credentials set opnsense`"
	}
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
