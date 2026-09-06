package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jpvelasco/nyx/internal/backends"
	"github.com/jpvelasco/nyx/internal/backends/system"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/jpvelasco/nyx/internal/topology"
)

// hermeticCreds pins the credential-resolution inputs for missing-credential
// tests: all provider env vars empty and an empty temp store, so no local
// ~/.nyx/credentials.json or dev machine env vars leak into assertions.
func hermeticCreds(t *testing.T) {
	t.Helper()
	for _, k := range []string{"OMADA_HOST", "OMADA_CLIENT_ID", "OMADA_CLIENT_SECRET", "OMADA_SITE", "OPNSENSE_HOST", "OPNSENSE_API_KEY", "OPNSENSE_API_SECRET"} {
		t.Setenv(k, "")
	}
	t.Setenv("NYX_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials.json"))
}

// credEnvReaders wires the env-var layer of credential resolution to the real
// process environment so dispatch tests observe the full fallback chain.
func credEnvReaders() (omada, opnsense map[string]func(string) string) {
	omada = map[string]func(string) string{
		"OMADA_HOST": os.Getenv, "OMADA_CLIENT_ID": os.Getenv,
		"OMADA_CLIENT_SECRET": os.Getenv, "OMADA_SITE": os.Getenv,
	}
	opnsense = map[string]func(string) string{
		"OPNSENSE_HOST": os.Getenv, "OPNSENSE_API_KEY": os.Getenv,
		"OPNSENSE_API_SECRET": os.Getenv,
	}
	return omada, opnsense
}

func newTestServer() *Server {
	omada, opnsense := credEnvReaders()
	return &Server{
		reader:          &bytes.Buffer{},
		writer:          &bytes.Buffer{},
		checkSvc:        service.NewCheckService(),
		omadaSvc:        service.NewOmadaService(),
		credEnv:         omada,
		opnsenseCredEnv: opnsense,
	}
}

func TestNewServer(t *testing.T) {
	server := NewServer()
	if server == nil {
		t.Fatal("expected non-nil server")
	}
	if server.reader == nil || server.writer == nil {
		t.Error("NewServer must wire stdin/stdout")
	}
	if server.checkSvc == nil {
		t.Error("NewServer must create a CheckService")
	}
	if server.initialized {
		t.Error("new server must start uninitialized")
	}
}

func TestServe_EndToEnd(t *testing.T) {
	var in bytes.Buffer
	var out bytes.Buffer
	server := &Server{reader: &in, writer: &out, checkSvc: service.NewCheckService()}

	in.WriteString(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n")
	in.WriteString(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}` + "\n")
	in.WriteString(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"nope","arguments":{}}}` + "\n")
	in.WriteString(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n")
	in.WriteString(`not-json` + "\n")
	in.WriteString("\n")
	in.WriteString(`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"discover_subnet","arguments":{}}}` + "\n")

	if err := server.Serve(context.Background()); err != nil {
		t.Fatalf("Serve returned error: %v", err)
	}

	lines := nonEmptyLines(out.String())
	if len(lines) != 5 {
		t.Fatalf("expected 5 responses, got %d: %q", len(lines), out.String())
	}
	for i, wantID := range []string{"1", "2", "3"} {
		if !strings.Contains(lines[i], `"id":`+wantID) {
			t.Errorf("response %d: expected id %s, got %s", i, wantID, lines[i])
		}
	}
	if !strings.Contains(lines[1], `"tools"`) {
		t.Errorf("tools/list response should contain tools, got %s", lines[1])
	}
	if !strings.Contains(lines[2], `"unknown tool: nope"`) || !strings.Contains(lines[2], `"isError":true`) {
		t.Errorf("expected unknown tool error, got %s", lines[2])
	}
	if !strings.Contains(lines[3], `-32700`) || !strings.Contains(lines[3], `parse error`) {
		t.Errorf("expected parse error for malformed frame, got %s", lines[3])
	}
	if !strings.Contains(lines[4], `"id":4`) {
		t.Errorf("response 4: expected id 4, got %s", lines[4])
	}
	if !strings.Contains(lines[4], `"subnet parameter is required"`) {
		t.Errorf("expected required-param error for discover_subnet, got %s", lines[4])
	}
}

func TestServe_MalformedAndNotificationsSkipped(t *testing.T) {
	var in bytes.Buffer
	var out bytes.Buffer
	server := &Server{reader: &in, writer: &out, checkSvc: service.NewCheckService()}

	in.WriteString(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n")
	in.WriteString(`not-json` + "\n")
	in.WriteString("\n")
	in.WriteString(`{"jsonrpc":` + "\n")
	in.WriteString(`{"jsonrpc":"2.0","id":null,"method":"initialize"}` + "\n")

	if err := server.Serve(context.Background()); err != nil {
		t.Fatalf("Serve returned error: %v", err)
	}
	lines := nonEmptyLines(out.String())
	if len(lines) != 2 {
		t.Fatalf("expected 2 parse-error responses, got %d: %q", len(lines), out.String())
	}
	for i, line := range lines {
		if !strings.Contains(line, `-32700`) || !strings.Contains(line, `parse error`) {
			t.Errorf("response %d: expected parse error, got %s", i, line)
		}
		if !strings.Contains(line, `"id":null`) {
			t.Errorf("parse-error response %d must carry a null id, got %s", i, line)
		}
	}
}

func TestServe_OversizedFrame_ParseErrorAndContinue(t *testing.T) {
	var in bytes.Buffer
	var out bytes.Buffer
	server := &Server{reader: &in, writer: &out, checkSvc: service.NewCheckService()}

	// Crossing maxFrameSize mid-chunk (not on a 64KB boundary) exercises the
	// drain-then-error path; a trailing newline lets the drain succeed.
	in.WriteString(strings.Repeat("x", maxFrameSize+64*1024+1) + "\n")
	in.WriteString(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n")

	if err := server.Serve(context.Background()); err != nil {
		t.Fatalf("Serve returned error: %v", err)
	}
	lines := nonEmptyLines(out.String())
	if len(lines) != 2 {
		t.Fatalf("expected 2 responses, got %d: %q", len(lines), out.String())
	}
	if !strings.Contains(lines[0], `-32700`) || !strings.Contains(lines[0], `parse error`) {
		t.Errorf("expected parse error for oversized frame, got %s", lines[0])
	}
	if !strings.Contains(lines[1], `"id":1`) {
		t.Errorf("server must keep serving after an oversized frame, got %s", lines[1])
	}
}

func TestServe_NoTrailingNewline(t *testing.T) {
	// The final frame may lack a trailing newline; it must still be processed
	// before Serve returns on EOF.
	var in bytes.Buffer
	var out bytes.Buffer
	server := &Server{reader: &in, writer: &out, checkSvc: service.NewCheckService()}

	in.WriteString(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)

	if err := server.Serve(context.Background()); err != nil {
		t.Fatalf("Serve returned error: %v", err)
	}
	lines := nonEmptyLines(out.String())
	if len(lines) != 1 {
		t.Fatalf("expected 1 response, got %d: %q", len(lines), out.String())
	}
	if !strings.Contains(lines[0], `"id":1`) {
		t.Errorf("final frame without newline must be processed, got %s", lines[0])
	}
}

func TestServe_OversizedFrame_NoTrailingNewline(t *testing.T) {
	// An oversized final frame with no trailing newline: the drain ends at
	// EOF and Serve must terminate cleanly instead of hanging or panicking.
	var in bytes.Buffer
	var out bytes.Buffer
	server := &Server{reader: &in, writer: &out, checkSvc: service.NewCheckService()}

	in.WriteString(strings.Repeat("x", maxFrameSize+64*1024+1))

	if err := server.Serve(context.Background()); err != nil {
		t.Fatalf("Serve returned error: %v", err)
	}
	if out.Len() != 0 {
		t.Errorf("expected no responses for oversized EOF-terminated frame, got %q", out.String())
	}
}

func TestServe_ScannerErrorPropagated(t *testing.T) {
	server := &Server{reader: &failingReader{}, writer: &bytes.Buffer{}, checkSvc: service.NewCheckService()}
	err := server.Serve(context.Background())
	if err == nil {
		t.Fatal("expected error from failing reader")
	}
}

func TestServe_ToolsCallBeforeInitialize(t *testing.T) {
	var in bytes.Buffer
	var out bytes.Buffer
	server := &Server{reader: &in, writer: &out, checkSvc: service.NewCheckService()}
	in.WriteString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"discover_subnet","arguments":{}}}` + "\n")
	if err := server.Serve(context.Background()); err != nil {
		t.Fatalf("Serve returned error: %v", err)
	}
	lines := nonEmptyLines(out.String())
	if len(lines) != 1 {
		t.Fatalf("expected 1 response, got %d", len(lines))
	}
	if !strings.Contains(lines[0], `-32002`) {
		t.Errorf("expected not-initialized error, got %s", lines[0])
	}
}

func TestHandleInitialize(t *testing.T) {
	req := &jsonRPCRequest{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "initialize"}
	resp := newTestServer().handleInitialize(req)
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	if string(resp.ID) != "1" {
		t.Errorf("ID = %s, want 1", resp.ID)
	}
	result, ok := resp.Result.(initializeResult)
	if !ok {
		t.Fatalf("expected initializeResult, got %T", resp.Result)
	}
	if result.ProtocolVersion != "2024-11-05" {
		t.Errorf("protocolVersion = %q", result.ProtocolVersion)
	}
	if _, ok := result.Capabilities["tools"]; !ok {
		t.Error("capabilities should advertise tools")
	}
	if result.ServerInfo.Name != "nyx" {
		t.Errorf("server name = %q", result.ServerInfo.Name)
	}
	if result.ServerInfo.Version == "" {
		t.Error("server version should be set")
	}
}

func TestHandleRequest_SetsInitialized(t *testing.T) {
	server := newTestServer()
	server.handleRequest(context.Background(), &jsonRPCRequest{ID: json.RawMessage(`1`), Method: "initialize"})
	if !server.initialized {
		t.Error("handleRequest(initialize) should set initialized")
	}
}

func TestHandleRequest_UnknownMethod(t *testing.T) {
	resp := newTestServer().handleRequest(context.Background(), &jsonRPCRequest{ID: json.RawMessage(`1`), Method: "bogus"})
	if resp.Error == nil {
		t.Fatal("expected error")
	}
	if resp.Error.Code != -32601 {
		t.Errorf("code = %d, want -32601", resp.Error.Code)
	}
	if !strings.Contains(resp.Error.Message, "bogus") {
		t.Errorf("message = %q", resp.Error.Message)
	}
}

func TestHandleToolsList_NotInitialized(t *testing.T) {
	resp := newTestServer().handleToolsList(&jsonRPCRequest{ID: json.RawMessage(`1`)})
	if resp.Error == nil || resp.Error.Code != -32002 {
		t.Fatalf("expected -32002, got %+v", resp.Error)
	}
}

func TestHandleToolsList_Shape(t *testing.T) {
	server := newTestServer()
	server.handleInitialize(&jsonRPCRequest{ID: json.RawMessage(`1`)})
	resp := server.handleToolsList(&jsonRPCRequest{ID: json.RawMessage(`2`)})
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	list, ok := resp.Result.(toolsListResult)
	if !ok {
		t.Fatalf("expected toolsListResult, got %T", resp.Result)
	}
	if len(list.Tools) != 44 {
		t.Fatalf("expected 44 tools, got %d", len(list.Tools))
	}
	names := map[string]string{}
	for _, tl := range list.Tools {
		names[tl.Name] = tl.Description
		if tl.InputSchema.Type != "object" {
			t.Errorf("tool %s: schema type = %q", tl.Name, tl.InputSchema.Type)
		}
	}
	for _, want := range []string{"discover_subnet", "check_routes", "check_vpn", "verify_isolation", "run_audit", "load_spec", "get_interfaces", "ping_target", "run_doctor", "provider_list", "omada_get_info", "omada_list_networks", "omada_list_acls", "omada_list_clients", "omada_inventory", "omada_import", "omada_plan", "omada_apply_acl", "omada_list_port_forwardings", "omada_list_one_to_one_nat", "omada_get_nat_settings", "omada_nat_facts", "omada_get_uplink_info", "omada_list_switch_ports", "omada_list_lan_profiles", "omada_list_gateway_dhcp_users", "omada_get_client_topology", "omada_plan_port", "omada_apply_port_profile", "opnsense_get_info", "opnsense_list_interfaces", "opnsense_list_firewall_rules", "opnsense_list_clients", "opnsense_list_port_forward_rules", "opnsense_list_one_to_one_rules", "opnsense_list_source_nat_rules", "opnsense_list_aliases", "opnsense_get_nat", "opnsense_plan_nat", "opnsense_apply_nat", "opnsense_list_services", "opnsense_list_gateways", "opnsense_inventory", "topology"} {
		if _, ok := names[want]; !ok {
			t.Errorf("missing tool %q", want)
		}
	}
	dc := list.Tools[0]
	if len(dc.InputSchema.Required) != 1 || dc.InputSchema.Required[0] != "subnet" {
		t.Errorf("discover_subnet required = %v", dc.InputSchema.Required)
	}
}

// BDD S3.1 — credential arguments are optional in the input schemas: the
// tools/list Required lists carry only the arguments that have no env/store
// fallback, so an agent with configured credentials need not pass them.
func TestHandleToolsList_SchemaCredentialsOptional(t *testing.T) {
	server := newTestServer()
	server.handleInitialize(&jsonRPCRequest{ID: json.RawMessage(`1`)})
	resp := server.handleToolsList(&jsonRPCRequest{ID: json.RawMessage(`2`)})
	list, ok := resp.Result.(toolsListResult)
	if !ok {
		t.Fatalf("expected toolsListResult, got %T", resp.Result)
	}
	byName := map[string]tool{}
	for _, tl := range list.Tools {
		byName[tl.Name] = tl
	}

	want := map[string][]string{
		"omada_list_networks":              {"host"},
		"omada_list_acls":                  {"host"},
		"omada_list_clients":               {"host"},
		"omada_inventory":                  {"host"},
		"omada_import":                     {"host"},
		"omada_plan":                       {"host", "spec"},
		"omada_apply_acl":                  {"host", "from", "to", "action"},
		"omada_list_port_forwardings":      {"host"},
		"omada_list_one_to_one_nat":        {"host"},
		"omada_get_nat_settings":           {"host"},
		"omada_nat_facts":                  {"host"},
		"omada_get_uplink_info":            {"host", "device_mac"},
		"omada_list_switch_ports":          {"host"},
		"omada_list_lan_profiles":          {"host"},
		"omada_list_gateway_dhcp_users":    {"host", "gateway_mac"},
		"omada_get_client_topology":        {"host", "client_mac"},
		"omada_plan_port":                  {"host", "switch_mac", "port", "native"},
		"omada_apply_port_profile":         {"host", "switch_mac", "port", "native"},
		"opnsense_get_info":                {"host"},
		"opnsense_list_interfaces":         {"host"},
		"opnsense_list_services":           {"host"},
		"opnsense_list_gateways":           {"host"},
		"opnsense_list_firewall_rules":     {"host"},
		"opnsense_list_clients":            {"host"},
		"opnsense_list_port_forward_rules": {"host"},
		"opnsense_list_one_to_one_rules":   {"host"},
		"opnsense_list_source_nat_rules":   {"host"},
		"opnsense_list_aliases":            {"host"},
		"opnsense_get_nat":                 {"host"},
		"opnsense_plan_nat":                {"host", "operation"},
		"opnsense_apply_nat":               {"host", "operation"},
	}
	for name, wantReq := range want {
		tl, ok := byName[name]
		if !ok {
			t.Errorf("missing tool %q", name)
			continue
		}
		if got := tl.InputSchema.Required; !equalStrings(got, wantReq) {
			t.Errorf("%s required = %v, want %v", name, got, wantReq)
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestHandleToolCall_NotInitialized(t *testing.T) {
	resp := newTestServer().handleToolCall(context.Background(), &jsonRPCRequest{ID: json.RawMessage(`1`)})
	if resp.Error == nil || resp.Error.Code != -32002 {
		t.Fatalf("expected -32002, got %+v", resp.Error)
	}
}

func TestHandleToolCall_Timeout(t *testing.T) {
	old := toolCallTimeout
	toolCallTimeout = 50 * time.Millisecond
	defer func() { toolCallTimeout = old }()

	svc := &blockingOmadaSvc{started: make(chan struct{})}
	server := &Server{reader: &bytes.Buffer{}, writer: &bytes.Buffer{}, checkSvc: service.NewCheckService(), omadaSvc: svc}
	server.initialized = true

	resp := server.handleToolCall(context.Background(), &jsonRPCRequest{
		ID:     json.RawMessage(`9`),
		Params: json.RawMessage(`{"name":"omada_get_info","arguments":{"host":"omada.local"}}`),
	})
	if resp.Error == nil || resp.Error.Code != -32000 {
		t.Fatalf("expected -32000 timeout error, got %+v", resp.Error)
	}
	if !strings.Contains(resp.Error.Message, "timed out after") || !strings.Contains(resp.Error.Message, "omada_get_info") {
		t.Errorf("message = %q", resp.Error.Message)
	}
	if string(resp.ID) != "9" {
		t.Errorf("ID = %s, want 9", resp.ID)
	}
}

func TestServe_ContinuesAfterToolCallTimeout(t *testing.T) {
	old := toolCallTimeout
	toolCallTimeout = 50 * time.Millisecond
	defer func() { toolCallTimeout = old }()

	var in bytes.Buffer
	var out bytes.Buffer
	server := &Server{reader: &in, writer: &out, checkSvc: service.NewCheckService(), omadaSvc: &blockingOmadaSvc{started: make(chan struct{})}}
	server.initialized = true

	in.WriteString(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"omada_get_info","arguments":{"host":"omada.local"}}}` + "\n")
	in.WriteString(`{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}` + "\n")

	if err := server.Serve(context.Background()); err != nil {
		t.Fatalf("Serve returned error: %v", err)
	}
	lines := nonEmptyLines(out.String())
	if len(lines) != 2 {
		t.Fatalf("expected 2 responses, got %d: %q", len(lines), out.String())
	}
	if !strings.Contains(lines[0], `-32000`) {
		t.Errorf("expected timeout error for hung tool call, got %s", lines[0])
	}
	if !strings.Contains(lines[1], `"id":2`) || !strings.Contains(lines[1], `"tools"`) {
		t.Errorf("server must stay responsive after a timeout, got %s", lines[1])
	}
}

func TestHandleToolCall_InvalidParams(t *testing.T) {
	server := newTestServer()
	server.initialized = true
	resp := server.handleToolCall(context.Background(), &jsonRPCRequest{ID: json.RawMessage(`1`), Params: json.RawMessage(`not-json`)})
	if resp.Error == nil || resp.Error.Code != -32602 {
		t.Fatalf("expected -32602, got %+v", resp.Error)
	}
}

func TestHandleToolCall_SuccessShape(t *testing.T) {
	server := newTestServer()
	server.initialized = true
	resp := server.handleToolCall(context.Background(), &jsonRPCRequest{
		ID:     json.RawMessage(`5`),
		Params: json.RawMessage(`{"name":"load_spec","arguments":{"spec_file":"` + strings.ReplaceAll(filepath.Join(t.TempDir(), "missing.yaml"), `\`, `\\`) + `"}}`),
	})
	if resp.Error != nil {
		t.Fatalf("unexpected json-rpc error: %v", resp.Error)
	}
	result, ok := resp.Result.(toolCallResult)
	if !ok {
		t.Fatalf("expected toolCallResult, got %T", resp.Result)
	}
	if !result.IsError {
		t.Error("load_spec of missing file should be a tool error")
	}
	if len(result.Content) != 1 || result.Content[0].Type != "text" {
		t.Errorf("content = %+v", result.Content)
	}
}

func TestDispatchDiscoverSubnet_EmptySubnet(t *testing.T) {
	text, isErr := newTestServer().DispatchToolForTest(context.Background(), "discover_subnet", map[string]interface{}{})
	if !isErr || !strings.Contains(text, "subnet parameter") {
		t.Errorf("got (%q, %v)", text, isErr)
	}
}

func TestDispatchDiscoverSubnet_TimingRange(t *testing.T) {
	text, isErr := newTestServer().DispatchToolForTest(context.Background(), "discover_subnet", map[string]interface{}{
		"subnet":        "not-a-cidr",
		"scan_timing":   3.0,
		"scan_min_rate": 100.0,
	})
	if !isErr {
		t.Fatal("expected error for invalid CIDR before nmap spawn")
	}
	if !strings.Contains(text, "discovery failed") {
		t.Errorf("text = %q", text)
	}
}

func TestDispatchCheckRoutes_EmptyTarget(t *testing.T) {
	text, isErr := newTestServer().DispatchToolForTest(context.Background(), "check_routes", map[string]interface{}{})
	if !isErr || !strings.Contains(text, "target parameter") {
		t.Errorf("got (%q, %v)", text, isErr)
	}
}

func TestDispatchCheckRoutes_ValidTarget(t *testing.T) {
	text, isErr := newTestServer().DispatchToolForTest(context.Background(), "check_routes", map[string]interface{}{
		"target": "127.0.0.1",
	})
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, `"target": "127.0.0.1"`) {
		t.Errorf("result should reference target: %s", text)
	}
}

func TestDispatchCheckRoutes_BackendError(t *testing.T) {
	server := &Server{reader: &bytes.Buffer{}, writer: &bytes.Buffer{}, checkSvc: &service.CheckService{Backend: errBackend{}}}
	text, isErr := server.DispatchToolForTest(context.Background(), "check_routes", map[string]interface{}{"target": "10.0.0.1"})
	if !isErr {
		t.Fatal("expected error flag for backend failure")
	}
	if !strings.Contains(text, "failed to get route") {
		t.Errorf("expected route failure text, got: %s", text)
	}
}

func TestDispatchCheckVPN_BackendError(t *testing.T) {
	server := &Server{checkSvc: &service.CheckService{Backend: errBackend{}}}
	text, isErr := server.DispatchToolForTest(context.Background(), "check_vpn", map[string]interface{}{"target": "10.0.0.1"})
	if !isErr {
		t.Fatal("expected error for backend failure")
	}
	if !strings.Contains(text, "failed to get route") {
		t.Errorf("error = %q", text)
	}
}

func TestDispatchCheckVPN_EmptyTarget(t *testing.T) {
	text, isErr := newTestServer().DispatchToolForTest(context.Background(), "check_vpn", map[string]interface{}{})
	if !isErr || !strings.Contains(text, "target parameter is required") {
		t.Errorf("got (%q, %v)", text, isErr)
	}
}

func TestDispatchCheckVPN_Routes(t *testing.T) {
	text, isErr := newTestServer().DispatchToolForTest(context.Background(), "check_vpn", map[string]interface{}{
		"target": "127.0.0.1",
	})
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, `"target": "127.0.0.1"`) {
		t.Errorf("result should reference target: %s", text)
	}
}

func TestDispatchVerifyIsolation_MissingParams(t *testing.T) {
	server := newTestServer()
	if text, isErr := server.DispatchToolForTest(context.Background(), "verify_isolation", map[string]interface{}{}); !isErr || !strings.Contains(text, "from parameter") {
		t.Errorf("from-missing: (%q, %v)", text, isErr)
	}
	if text, isErr := server.DispatchToolForTest(context.Background(), "verify_isolation", map[string]interface{}{"from": "lan"}); !isErr || !strings.Contains(text, "to parameter") {
		t.Errorf("to-missing: (%q, %v)", text, isErr)
	}
}

func TestDispatchVerifyIsolation_NilSpecUsesPing(t *testing.T) {
	text, isErr := newTestServer().DispatchToolForTest(context.Background(), "verify_isolation", map[string]interface{}{
		"from": "lan",
		"to":   "127.0.0.1",
	})
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, `"reachable"`) {
		t.Errorf("expected ping result, got: %s", text)
	}
}

func TestDispatchVerifyIsolation_BadSpecFile(t *testing.T) {
	text, isErr := newTestServer().DispatchToolForTest(context.Background(), "verify_isolation", map[string]interface{}{
		"from":      "lan",
		"to":        "iot",
		"spec_file": filepath.Join(t.TempDir(), "missing.yaml"),
	})
	if !isErr || !strings.Contains(text, "failed to load spec") {
		t.Errorf("got (%q, %v)", text, isErr)
	}
}

func TestDispatchVerifyIsolation_WithSpecFile(t *testing.T) {
	sp, err := os.CreateTemp(t.TempDir(), "spec-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sp.WriteString(`version: 1
site: test
networks:
  - name: lan
    cidr: 127.0.0.1/32
  - name: iot
    cidr: 127.0.0.2/32
assertions:
  - type: isolation
    from: lan
    to: iot
    expect: deny
`); err != nil {
		t.Fatal(err)
	}
	if err := sp.Close(); err != nil {
		t.Fatal(err)
	}
	text, isErr := newTestServer().DispatchToolForTest(context.Background(), "verify_isolation", map[string]interface{}{
		"from":      "lan",
		"to":        "iot",
		"spec_file": sp.Name(),
	})
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, `"check_type": "isolation"`) {
		t.Errorf("expected isolation finding, got: %s", text)
	}
}

func TestDispatchRunAudit_MissingAndBadSpecs(t *testing.T) {
	server := newTestServer()
	if text, isErr := server.DispatchToolForTest(context.Background(), "run_audit", map[string]interface{}{}); !isErr || !strings.Contains(text, "spec_file parameter") {
		t.Errorf("missing: (%q, %v)", text, isErr)
	}
	if text, isErr := server.DispatchToolForTest(context.Background(), "run_audit", map[string]interface{}{"spec_file": filepath.Join(t.TempDir(), "missing.yaml")}); !isErr || !strings.Contains(text, "failed to load spec") {
		t.Errorf("bad spec: (%q, %v)", text, isErr)
	}
}

func TestDispatchLoadSpec(t *testing.T) {
	server := newTestServer()
	if text, isErr := server.DispatchToolForTest(context.Background(), "load_spec", map[string]interface{}{}); !isErr || !strings.Contains(text, "spec_file parameter") {
		t.Errorf("missing: (%q, %v)", text, isErr)
	}
	sp, err := os.CreateTemp(t.TempDir(), "spec-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sp.WriteString("version: 1\nsite: test\n"); err != nil {
		t.Fatal(err)
	}
	if err := sp.Close(); err != nil {
		t.Fatal(err)
	}
	text, isErr := server.DispatchToolForTest(context.Background(), "load_spec", map[string]interface{}{"spec_file": sp.Name()})
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, `"site": "test"`) {
		t.Errorf("expected parsed spec, got: %s", text)
	}
}

func TestDispatchGetInterfaces(t *testing.T) {
	text, isErr := newTestServer().DispatchToolForTest(context.Background(), "get_interfaces", map[string]interface{}{})
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, `"`+"name"+`"`) {
		t.Errorf("expected interfaces JSON, got: %s", text)
	}
}

func TestDispatchPingTarget(t *testing.T) {
	text, isErr := newTestServer().DispatchToolForTest(context.Background(), "ping_target", map[string]interface{}{
		"target": "127.0.0.1",
	})
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, `"reachable"`) {
		t.Errorf("expected ping result, got: %s", text)
	}
}

func TestDispatchPingTarget_CancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	text, isErr := newTestServer().DispatchToolForTest(ctx, "ping_target", map[string]interface{}{
		"target": "127.0.0.1",
	})
	if !isErr {
		t.Fatal("expected error for cancelled context")
	}
	if !strings.Contains(text, "ping failed") {
		t.Errorf("error = %q", text)
	}
}

func TestDispatchPingTarget_EmptyTarget(t *testing.T) {
	text, isErr := newTestServer().DispatchToolForTest(context.Background(), "ping_target", map[string]interface{}{})
	if !isErr || !strings.Contains(text, "target parameter") {
		t.Errorf("got (%q, %v)", text, isErr)
	}
}

func TestDispatchVerifyIsolation_PingError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	text, isErr := newTestServer().DispatchToolForTest(ctx, "verify_isolation", map[string]interface{}{
		"from": "lan",
		"to":   "127.0.0.1",
	})
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, "could not determine isolation") {
		t.Errorf("expected warn result, got: %s", text)
	}
}

func TestDispatchProviderList_RegisteredProviders(t *testing.T) {
	providers.Reset()
	t.Cleanup(providers.Reset)
	if err := providers.Register(&dummyProvider{}); err != nil {
		t.Fatal(err)
	}
	text, isErr := newTestServer().DispatchToolForTest(context.Background(), "provider_list", map[string]interface{}{})
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, `"name": "dummy"`) || !strings.Contains(text, `"capabilities"`) {
		t.Errorf("expected registered provider in list, got: %s", text)
	}
}

func TestDispatchRunDoctor(t *testing.T) {
	if text, isErr := newTestServer().DispatchToolForTest(context.Background(), "run_doctor", map[string]interface{}{}); isErr {
		t.Fatalf("unexpected error: %s", text)
	}
}

func TestDispatchRunDoctor_WithSpecFile(t *testing.T) {
	sp, err := os.CreateTemp(t.TempDir(), "spec-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sp.WriteString("version: 1\nsite: test\nprobes:\n  - name: p1\n    host: 192.0.2.1\n    user: admin\n"); err != nil {
		t.Fatal(err)
	}
	if err := sp.Close(); err != nil {
		t.Fatal(err)
	}
	text, isErr := newTestServer().DispatchToolForTest(context.Background(), "run_doctor", map[string]interface{}{
		"spec_file": sp.Name(),
	})
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, "spec_file") || !strings.Contains(text, "nmap_installed") || !strings.Contains(text, "probe_reachable") {
		t.Errorf("expected nmap + spec + probe checks, got: %s", text)
	}
}

func TestDispatchRunDoctor_MissingSpecFile(t *testing.T) {
	text, isErr := newTestServer().DispatchToolForTest(context.Background(), "run_doctor", map[string]interface{}{
		"spec_file": filepath.Join(t.TempDir(), "missing.yaml"),
	})
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, "cannot read spec file") {
		t.Errorf("expected spec failure finding, got: %s", text)
	}
}

func TestDispatchProviderList(t *testing.T) {
	text, isErr := newTestServer().DispatchToolForTest(context.Background(), "provider_list", map[string]interface{}{})
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, `"capabilities"`) && !strings.Contains(text, `[]`) {
		t.Errorf("expected provider list JSON, got: %s", text)
	}
}

func TestDispatchUnknownTool(t *testing.T) {
	text, isErr := newTestServer().DispatchToolForTest(context.Background(), "bogus", map[string]interface{}{})
	if !isErr || !strings.Contains(text, "unknown tool") {
		t.Errorf("got (%q, %v)", text, isErr)
	}
}

func TestToJSON(t *testing.T) {
	text := toJSON(map[string]int{"a": 1})
	if !strings.Contains(text, `"a": 1`) {
		t.Errorf("text = %q", text)
	}
}

func TestToJSON_MarshalError(t *testing.T) {
	text := toJSON(make(chan int))
	if !strings.Contains(text, "json marshal error") {
		t.Errorf("expected marshal error text, got %q", text)
	}
}

func TestDispatchGetInterfaces_BackendError(t *testing.T) {
	server := &Server{checkSvc: &service.CheckService{Backend: errBackend{}}}
	text, isErr := server.DispatchToolForTest(context.Background(), "get_interfaces", map[string]interface{}{})
	if !isErr {
		t.Fatal("expected error for backend failure")
	}
	if !strings.Contains(text, "failed to get interfaces") {
		t.Errorf("error = %q", text)
	}
}

func TestDispatchOmadaGetInfo_MissingHost(t *testing.T) {
	hermeticCreds(t)
	text, isErr := newTestServer().DispatchToolForTest(context.Background(), "omada_get_info", map[string]interface{}{})
	if !isErr || !strings.Contains(text, "host parameter is required") {
		t.Errorf("got (%q, %v)", text, isErr)
	}
}

func TestDispatchOmadaGetInfo_Success(t *testing.T) {
	stub := &stubOmadaSvc{info: &service.OmadaInfo{Provider: "omada", Version: "6.4.5.1", APIVersion: "2.0", OmadaCID: "abc123", Configured: true}}
	server := serverWithOmadaStub(stub)
	text, isErr := server.DispatchToolForTest(context.Background(), "omada_get_info", map[string]interface{}{
		"host":            "omada.local",
		"skip_tls_verify": true,
		"ca_cert_path":    "ca.pem",
	})
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, `"provider": "omada"`) || !strings.Contains(text, `"version": "6.4.5.1"`) {
		t.Errorf("expected info JSON, got: %s", text)
	}
	if stub.calls != 1 {
		t.Errorf("service calls = %d, want 1", stub.calls)
	}
	if stub.lastOpts.Host != "omada.local" || !stub.lastOpts.SkipTLSVerify || stub.lastOpts.CACertPath != "ca.pem" {
		t.Errorf("options = %+v", stub.lastOpts)
	}
	if stub.lastOpts.ClientSecret != "" {
		t.Error("get_info must not carry credentials")
	}
}

func TestDispatchOmadaGetInfo_ServiceError(t *testing.T) {
	stub := &stubOmadaSvc{err: errors.New("connection refused")}
	text, isErr := serverWithOmadaStub(stub).DispatchToolForTest(context.Background(), "omada_get_info", map[string]interface{}{
		"host": "omada.local",
	})
	if !isErr || !strings.Contains(text, "omada info request failed") {
		t.Errorf("got (%q, %v)", text, isErr)
	}
}

func TestDispatchOmadaListNetworks_MissingCredentials(t *testing.T) {
	hermeticCreds(t)
	text, isErr := newTestServer().DispatchToolForTest(context.Background(), "omada_list_networks", map[string]interface{}{
		"host": "omada.local",
	})
	if !isErr || !strings.Contains(text, "client_id and client_secret parameters are required") {
		t.Errorf("got (%q, %v)", text, isErr)
	}
}

func TestDispatchOmadaListNetworks_Success(t *testing.T) {
	stub := &stubOmadaSvc{networks: []service.OmadaNetwork{
		{ID: "n1", Name: "Trusted", VLANID: 10, CIDR: "10.0.10.0/24", Gateway: "10.0.10.1", DHCPEnabled: true},
	}}
	server := serverWithOmadaStub(stub)
	text, isErr := server.DispatchToolForTest(context.Background(), "omada_list_networks", map[string]interface{}{
		"host":          "omada.local",
		"client_id":     "cid-1",
		"client_secret": "pw",
		"site":          "HQ",
	})
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, `"name": "Trusted"`) || !strings.Contains(text, `"cidr": "10.0.10.0/24"`) {
		t.Errorf("expected network JSON, got: %s", text)
	}
	if stub.calls != 1 {
		t.Errorf("service calls = %d, want 1", stub.calls)
	}
	if stub.lastOpts.Host != "omada.local" || stub.lastOpts.ClientID != "cid-1" || stub.lastOpts.ClientSecret != "pw" || stub.lastOpts.Site != "HQ" {
		t.Errorf("options = %+v", stub.lastOpts)
	}
	if strings.Contains(text, "pw") {
		t.Error("tool output must not echo the client secret")
	}
}

func TestDispatchOmadaListGatewayDHCPUsers(t *testing.T) {
	stub := &stubOmadaSvc{dhcpUsers: []service.OmadaGatewayDHCPUser{
		{IP: "10.0.10.20", MAC: "aa-bb-cc-dd-ee-01", NetworkName: "Trusted"},
	}}
	text, isErr := serverWithOmadaStub(stub).DispatchToolForTest(context.Background(), "omada_list_gateway_dhcp_users", map[string]interface{}{
		"host": "omada.local", "client_id": "cid-1", "client_secret": "pw", "gateway_mac": "aa:bb:cc:dd:ee:00",
	})
	if isErr || !strings.Contains(text, `"ip": "10.0.10.20"`) || stub.lastGWMAC != "aa:bb:cc:dd:ee:00" {
		t.Fatalf("got (%q, %v) lastMAC=%q", text, isErr, stub.lastGWMAC)
	}
	text, isErr = serverWithOmadaStub(stub).DispatchToolForTest(context.Background(), "omada_list_gateway_dhcp_users", map[string]interface{}{
		"host": "omada.local", "client_id": "cid-1", "client_secret": "pw",
	})
	if !isErr || !strings.Contains(text, "gateway_mac parameter is required") {
		t.Errorf("missing mac = (%q, %v)", text, isErr)
	}
}

func TestDispatchOmadaGetClientTopology(t *testing.T) {
	stub := &stubOmadaSvc{topoNodes: []service.OmadaClientTopologyNode{
		{NodeType: "clientNode", MAC: "aa-bb-cc-dd-ee-01", SwitchPort: "8"},
	}}
	text, isErr := serverWithOmadaStub(stub).DispatchToolForTest(context.Background(), "omada_get_client_topology", map[string]interface{}{
		"host": "omada.local", "client_id": "cid-1", "client_secret": "pw", "client_mac": "aa:bb:cc:dd:ee:01",
	})
	if isErr || !strings.Contains(text, `"switch_port": "8"`) || stub.lastClientMAC != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("got (%q, %v) lastMAC=%q", text, isErr, stub.lastClientMAC)
	}
	text, isErr = serverWithOmadaStub(stub).DispatchToolForTest(context.Background(), "omada_get_client_topology", map[string]interface{}{
		"host": "omada.local", "client_id": "cid-1", "client_secret": "pw",
	})
	if !isErr || !strings.Contains(text, "client_mac parameter is required") {
		t.Errorf("missing mac = (%q, %v)", text, isErr)
	}
}

func TestDispatchOmadaListNetworks_ServiceError(t *testing.T) {
	stub := &stubOmadaSvc{err: errors.New("site not found")}
	text, isErr := serverWithOmadaStub(stub).DispatchToolForTest(context.Background(), "omada_list_networks", map[string]interface{}{
		"host":          "omada.local",
		"client_id":     "cid-1",
		"client_secret": "pw",
	})
	if !isErr || !strings.Contains(text, "omada networks request failed") {
		t.Errorf("got (%q, %v)", text, isErr)
	}
}

func TestDispatchOmadaListACLs_Success(t *testing.T) {
	stub := &stubOmadaSvc{acls: []service.OmadaACLRule{
		{ID: "a1", Name: "Block IoT", Enabled: true, Policy: "drop", SourceName: "iot", DestName: "trusted"},
	}}
	text, isErr := serverWithOmadaStub(stub).DispatchToolForTest(context.Background(), "omada_list_acls", map[string]interface{}{
		"host":          "omada.local",
		"client_id":     "cid-1",
		"client_secret": "pw",
	})
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, `"policy": "drop"`) || !strings.Contains(text, `"source_name": "iot"`) {
		t.Errorf("expected ACL JSON, got: %s", text)
	}
}

func TestDispatchOmadaListACLs_ServiceError(t *testing.T) {
	stub := &stubOmadaSvc{err: errors.New("no ACL endpoint")}
	text, isErr := serverWithOmadaStub(stub).DispatchToolForTest(context.Background(), "omada_list_acls", map[string]interface{}{
		"host":          "omada.local",
		"client_id":     "cid-1",
		"client_secret": "pw",
	})
	if !isErr || !strings.Contains(text, "omada acls request failed") {
		t.Errorf("got (%q, %v)", text, isErr)
	}
}

func TestDispatchOmadaListClients_Success(t *testing.T) {
	stub := &stubOmadaSvc{clients: []service.OmadaClient{
		{MAC: "aa:bb:cc:dd:ee:ff", IP: "10.0.10.5", Name: "nas", NetworkName: "Trusted", Type: "wired"},
	}}
	text, isErr := serverWithOmadaStub(stub).DispatchToolForTest(context.Background(), "omada_list_clients", map[string]interface{}{
		"host":          "omada.local",
		"client_id":     "cid-1",
		"client_secret": "pw",
	})
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, `"name": "nas"`) || !strings.Contains(text, `"network_name": "Trusted"`) {
		t.Errorf("expected client JSON, got: %s", text)
	}
}

func TestDispatchOmadaListClients_ServiceError(t *testing.T) {
	stub := &stubOmadaSvc{err: errors.New("getting clients")}
	text, isErr := serverWithOmadaStub(stub).DispatchToolForTest(context.Background(), "omada_list_clients", map[string]interface{}{
		"host":          "omada.local",
		"client_id":     "cid-1",
		"client_secret": "pw",
	})
	if !isErr || !strings.Contains(text, "omada clients request failed") {
		t.Errorf("got (%q, %v)", text, isErr)
	}
}

func TestDispatchOmadaInventory_Success(t *testing.T) {
	stub := &stubOmadaSvc{inventory: &service.OmadaInventory{
		Site:               "HQ",
		ControllerVersion:  "6.4.5.1",
		ControllerCategory: "advanced",
		NetworkGateways:    map[string]string{"trusted": "GW-CORE"},
		ClientCount:        7,
		Warnings:           []string{"clients unavailable: timeout"},
	}}
	server := serverWithOmadaStub(stub)
	text, isErr := server.DispatchToolForTest(context.Background(), "omada_inventory", map[string]interface{}{
		"host":          "omada.local",
		"client_id":     "cid-1",
		"client_secret": "pw",
		"site":          "HQ",
	})
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	for _, want := range []string{
		`"site": "HQ"`,
		`"controller_version": "6.4.5.1"`,
		`"controller_category": "advanced"`,
		`"trusted": "GW-CORE"`,
		`"client_count": 7`,
		`"clients unavailable: timeout"`,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("expected %s in output, got: %s", want, text)
		}
	}
	if stub.calls != 1 || stub.lastOpts.Site != "HQ" {
		t.Errorf("calls = %d, site = %q", stub.calls, stub.lastOpts.Site)
	}
	if strings.Contains(text, "pw") {
		t.Error("tool output must not echo the client secret")
	}
}

func TestDispatchOmadaInventory_MissingCredentials(t *testing.T) {
	hermeticCreds(t)
	text, isErr := newTestServer().DispatchToolForTest(context.Background(), "omada_inventory", map[string]interface{}{
		"host": "omada.local",
	})
	if !isErr || !strings.Contains(text, "client_id and client_secret parameters are required") {
		t.Errorf("got (%q, %v)", text, isErr)
	}
}

func TestDispatchOmadaInventory_ServiceError(t *testing.T) {
	stub := &stubOmadaSvc{err: errors.New("controller unreachable")}
	text, isErr := serverWithOmadaStub(stub).DispatchToolForTest(context.Background(), "omada_inventory", map[string]interface{}{
		"host":          "omada.local",
		"client_id":     "cid-1",
		"client_secret": "pw",
	})
	if !isErr || !strings.Contains(text, "omada inventory request failed") {
		t.Errorf("got (%q, %v)", text, isErr)
	}
}

func TestDispatchOmadaImport_MissingParams(t *testing.T) {
	hermeticCreds(t)
	server := newTestServer()
	if text, isErr := server.DispatchToolForTest(context.Background(), "omada_import", map[string]interface{}{}); !isErr || !strings.Contains(text, "host parameter is required") {
		t.Errorf("missing host: (%q, %v)", text, isErr)
	}
	if text, isErr := server.DispatchToolForTest(context.Background(), "omada_import", map[string]interface{}{"host": "omada.local"}); !isErr || !strings.Contains(text, "client_id and client_secret parameters are required") {
		t.Errorf("missing creds: (%q, %v)", text, isErr)
	}
}

func TestDispatchOmadaImport_Success(t *testing.T) {
	stub := &stubOmadaSvc{imp: &service.OmadaImport{
		Site: "HQ", ControllerVersion: "6.4.5.1", NetworkCount: 2, ACLRuleCount: 1, ClientCount: 1,
		Warnings: []string{"note"},
	}}
	text, isErr := serverWithOmadaStub(stub).DispatchToolForTest(context.Background(), "omada_import", map[string]interface{}{
		"host":          "omada.local",
		"client_id":     "cid-1",
		"client_secret": "pw",
		"site":          "HQ",
	})
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, `"network_count": 2`) || !strings.Contains(text, `"controller_version": "6.4.5.1"`) || !strings.Contains(text, `"warnings"`) {
		t.Errorf("expected import JSON, got: %s", text)
	}
	if stub.lastOpts.Site != "HQ" {
		t.Errorf("options = %+v", stub.lastOpts)
	}
	if strings.Contains(text, "pw") {
		t.Error("tool output must not echo the client secret")
	}
}

func TestDispatchOmadaImport_ServiceError(t *testing.T) {
	stub := &stubOmadaSvc{err: errors.New("import failed")}
	text, isErr := serverWithOmadaStub(stub).DispatchToolForTest(context.Background(), "omada_import", map[string]interface{}{
		"host":          "omada.local",
		"client_id":     "cid-1",
		"client_secret": "pw",
	})
	if !isErr || !strings.Contains(text, "omada import request failed") {
		t.Errorf("got (%q, %v)", text, isErr)
	}
}

func TestDispatchOmadaPlan_MissingParams(t *testing.T) {
	hermeticCreds(t)
	server := newTestServer()
	if text, isErr := server.DispatchToolForTest(context.Background(), "omada_plan", map[string]interface{}{}); !isErr || !strings.Contains(text, "host parameter is required") {
		t.Errorf("missing host: (%q, %v)", text, isErr)
	}
	if text, isErr := server.DispatchToolForTest(context.Background(), "omada_plan", map[string]interface{}{"host": "omada.local"}); !isErr || !strings.Contains(text, "client_id and client_secret parameters are required") {
		t.Errorf("missing creds: (%q, %v)", text, isErr)
	}
	if text, isErr := server.DispatchToolForTest(context.Background(), "omada_plan", map[string]interface{}{
		"host": "omada.local", "client_id": "cid-1", "client_secret": "pw",
	}); !isErr || !strings.Contains(text, "spec parameter is required") {
		t.Errorf("missing spec: (%q, %v)", text, isErr)
	}
}

func TestDispatchOmadaPlan_Success(t *testing.T) {
	stub := &stubOmadaSvc{plan: &service.OmadaPlan{
		Site: "HQ", ProposedSite: "HQ", CurrentRules: 3, ProposedRules: 4,
		ToAdd: []service.OmadaPolicyDiff{{From: "guest", To: "trusted", Action: "deny"}},
	}}
	text, isErr := serverWithOmadaStub(stub).DispatchToolForTest(context.Background(), "omada_plan", map[string]interface{}{
		"host":          "omada.local",
		"client_id":     "cid-1",
		"client_secret": "pw",
		"site":          "HQ",
		"spec":          "version: 1\nsite: HQ\npolicies: []\n",
	})
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, `"current_rules": 3`) || !strings.Contains(text, `"to_add"`) || !strings.Contains(text, `"from": "guest"`) {
		t.Errorf("expected plan JSON, got: %s", text)
	}
	if stub.lastOpts.Site != "HQ" {
		t.Errorf("options = %+v", stub.lastOpts)
	}
	if strings.Contains(text, "pw") {
		t.Error("tool output must not echo the client secret")
	}
}

func TestDispatchOmadaPlan_ServiceError(t *testing.T) {
	stub := &stubOmadaSvc{err: errors.New("plan failed")}
	text, isErr := serverWithOmadaStub(stub).DispatchToolForTest(context.Background(), "omada_plan", map[string]interface{}{
		"host":          "omada.local",
		"client_id":     "cid-1",
		"client_secret": "pw",
		"spec":          "version: 1\nsite: HQ\npolicies: []\n",
	})
	if !isErr || !strings.Contains(text, "omada plan request failed") {
		t.Errorf("got (%q, %v)", text, isErr)
	}
	if strings.Contains(text, "pw") {
		t.Error("error output must not echo the client secret")
	}
}

func TestDispatchOmadaApplyACL_MissingParams(t *testing.T) {
	hermeticCreds(t)
	server := newTestServer()
	if text, isErr := server.DispatchToolForTest(context.Background(), "omada_apply_acl", map[string]interface{}{}); !isErr || !strings.Contains(text, "host parameter is required") {
		t.Errorf("missing host: (%q, %v)", text, isErr)
	}
	if text, isErr := server.DispatchToolForTest(context.Background(), "omada_apply_acl", map[string]interface{}{"host": "omada.local"}); !isErr || !strings.Contains(text, "client_id and client_secret parameters are required") {
		t.Errorf("missing creds: (%q, %v)", text, isErr)
	}
	base := map[string]interface{}{"host": "omada.local", "client_id": "cid-1", "client_secret": "pw"}
	if text, isErr := server.DispatchToolForTest(context.Background(), "omada_apply_acl", base); !isErr || !strings.Contains(text, "from parameter is required") {
		t.Errorf("missing from: (%q, %v)", text, isErr)
	}
	if text, isErr := server.DispatchToolForTest(context.Background(), "omada_apply_acl", map[string]interface{}{
		"host": "omada.local", "client_id": "cid-1", "client_secret": "pw", "from": "iot",
	}); !isErr || !strings.Contains(text, "to parameter is required") {
		t.Errorf("missing to: (%q, %v)", text, isErr)
	}
	if text, isErr := server.DispatchToolForTest(context.Background(), "omada_apply_acl", map[string]interface{}{
		"host": "omada.local", "client_id": "cid-1", "client_secret": "pw", "from": "iot", "to": "trusted",
	}); !isErr || !strings.Contains(text, "action parameter is required") {
		t.Errorf("missing action: (%q, %v)", text, isErr)
	}
}

func TestDispatchOmadaApplyACL_Success(t *testing.T) {
	stub := &stubOmadaSvc{apply: &service.OmadaACLApplyResult{
		DryRun: true, Outcome: "created", RuleID: "a9",
		FromCIDRs: []string{"10.0.20.0/24"}, ToCIDRs: []string{"10.0.10.0/24"},
		Before: "[]", After: "[]",
	}}
	text, isErr := serverWithOmadaStub(stub).DispatchToolForTest(context.Background(), "omada_apply_acl", map[string]interface{}{
		"host": "omada.local", "client_id": "cid-1", "client_secret": "pw", "site": "HQ",
		"from": "iot", "to": "trusted", "action": "deny",
	})
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, `"dry_run": true`) || !strings.Contains(text, `"outcome": "created"`) || !strings.Contains(text, `"rule_id": "a9"`) {
		t.Errorf("expected apply JSON, got: %s", text)
	}
	if !stub.lastApplyReq.DryRun {
		t.Error("dry_run must default to true when the argument is absent")
	}
	if !sliceEq(stub.lastApplyReq.From, []string{"iot"}) || !sliceEq(stub.lastApplyReq.To, []string{"trusted"}) || stub.lastApplyReq.Action != "deny" {
		t.Errorf("apply request = %+v", stub.lastApplyReq)
	}
	if strings.Contains(text, "pw") {
		t.Error("tool output must not echo the client secret")
	}
}

func TestDispatchOmadaApplyACL_ExplicitApply(t *testing.T) {
	stub := &stubOmadaSvc{apply: &service.OmadaACLApplyResult{
		Outcome: "created", RuleID: "a9", FromCIDRs: []string{"10.0.20.0/24"}, ToCIDRs: []string{"10.0.10.0/24"},
		Before: "[]", After: "[{\"id\":\"a9\"}]",
		PostAudit: &service.OmadaPostAudit{Status: "pass", Summary: "isolation confirmed",
			Findings: []models.CheckResult{{CheckType: "isolation", Status: models.StatusPass, Summary: "isolation confirmed"}}},
	}}
	text, isErr := serverWithOmadaStub(stub).DispatchToolForTest(context.Background(), "omada_apply_acl", map[string]interface{}{
		"host": "omada.local", "client_id": "cid-1", "client_secret": "pw",
		"from": "iot", "to": "trusted", "action": "deny", "dry_run": false, "post_audit": false,
	})
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if stub.lastApplyReq.DryRun {
		t.Error("dry_run must be false when explicitly set")
	}
	if stub.lastApplyReq.PostAudit {
		t.Error("post_audit must be false when explicitly set")
	}
	if !strings.Contains(text, `"outcome": "created"`) {
		t.Errorf("expected apply JSON, got: %s", text)
	}
}

func TestDispatchOmadaApplyACL_ScopeProtocolsAndList(t *testing.T) {
	stub := &stubOmadaSvc{apply: &service.OmadaACLApplyResult{
		Outcome: "created", RuleID: "a9", Scope: "gateway",
		FromCIDRs: []string{"10.0.20.0/24"}, ToCIDRs: []string{"10.0.10.0/24", "10.0.30.0/24"},
		Before: "[]", After: "[{\"id\":\"a9\"}]",
	}}
	text, isErr := serverWithOmadaStub(stub).DispatchToolForTest(context.Background(), "omada_apply_acl", map[string]interface{}{
		"host": "omada.local", "client_id": "cid-1", "client_secret": "pw",
		"from": "iot", "to": "trusted, guest", "action": "deny",
		"scope": "gateway", "protocols": "6, 17", "dry_run": true,
	})
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !sliceEq(stub.lastApplyReq.To, []string{"trusted", "guest"}) {
		t.Errorf("to = %v, want comma list split and trimmed", stub.lastApplyReq.To)
	}
	if stub.lastApplyReq.Scope != "gateway" {
		t.Errorf("scope = %q, want gateway", stub.lastApplyReq.Scope)
	}
	if !sliceEqInt(stub.lastApplyReq.Protocols, []int{6, 17}) {
		t.Errorf("protocols = %v, want [6 17]", stub.lastApplyReq.Protocols)
	}
}

func TestDispatchOmadaApplyACL_InvalidProtocols(t *testing.T) {
	stub := &stubOmadaSvc{}
	text, isErr := serverWithOmadaStub(stub).DispatchToolForTest(context.Background(), "omada_apply_acl", map[string]interface{}{
		"host": "omada.local", "client_id": "cid-1", "client_secret": "pw",
		"from": "iot", "to": "trusted", "action": "deny", "protocols": "6, tcp",
	})
	if !isErr || !strings.Contains(text, "protocols") {
		t.Errorf("got (%q, %v), want protocols parse error", text, isErr)
	}
	if stub.calls != 0 {
		t.Error("service must not be called for a malformed request")
	}
}

func TestDispatchOmadaApplyACL_ServiceError(t *testing.T) {
	stub := &stubOmadaSvc{err: errors.New("apply failed")}
	text, isErr := serverWithOmadaStub(stub).DispatchToolForTest(context.Background(), "omada_apply_acl", map[string]interface{}{
		"host": "omada.local", "client_id": "cid-1", "client_secret": "pw",
		"from": "iot", "to": "trusted", "action": "deny",
	})
	if !isErr || !strings.Contains(text, "omada apply request failed") {
		t.Errorf("got (%q, %v)", text, isErr)
	}
	if strings.Contains(text, "pw") {
		t.Error("error output must not echo the client secret")
	}
}

func TestDispatchOpnsense_MissingParams(t *testing.T) {
	hermeticCreds(t)
	server := newTestServer()
	for _, tool := range []string{"opnsense_get_info", "opnsense_list_interfaces", "opnsense_list_firewall_rules", "opnsense_list_clients"} {
		if text, isErr := server.DispatchToolForTest(context.Background(), tool, map[string]interface{}{}); !isErr || !strings.Contains(text, "host parameter is required") {
			t.Errorf("%s missing host: (%q, %v)", tool, text, isErr)
		}
		if text, isErr := server.DispatchToolForTest(context.Background(), tool, map[string]interface{}{"host": "fw.local"}); !isErr || !strings.Contains(text, "api_key and api_secret parameters are required") {
			t.Errorf("%s missing creds: (%q, %v)", tool, text, isErr)
		}
	}
}

func TestDispatchOpnsenseGetInfo(t *testing.T) {
	stub := &stubOpnsenseSvc{info: &service.OpnsenseInfo{
		Provider: "opnsense", Version: "24.7.11", Product: "OPNsense", Arch: "amd64",
	}}
	text, isErr := serverWithOpnsenseStub(stub).DispatchToolForTest(context.Background(), "opnsense_get_info", map[string]interface{}{
		"host": "fw.local", "api_key": "key1", "api_secret": "secret1",
	})
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, `"version": "24.7.11"`) {
		t.Errorf("expected info JSON, got: %s", text)
	}
	if stub.lastOpts.Host != "fw.local" {
		t.Errorf("options = %+v", stub.lastOpts)
	}
	if strings.Contains(text, "secret1") {
		t.Error("tool output must not echo the API secret")
	}
}

func TestDispatchOpnsenseListInterfaces(t *testing.T) {
	stub := &stubOpnsenseSvc{interfaces: []service.OpnsenseInterface{
		{Name: "lan", IP: "10.0.10.1", Subnet: 24, Gateway: "10.0.10.1"},
	}}
	text, isErr := serverWithOpnsenseStub(stub).DispatchToolForTest(context.Background(), "opnsense_list_interfaces", map[string]interface{}{
		"host": "fw.local", "api_key": "key1", "api_secret": "secret1",
	})
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, `"name": "lan"`) || !strings.Contains(text, `"subnet": 24`) {
		t.Errorf("expected interfaces JSON, got: %s", text)
	}
}

func TestDispatchOpnsenseListFirewallRules(t *testing.T) {
	stub := &stubOpnsenseSvc{rules: []service.OpnsenseFirewallRule{
		{UUID: "u1", Action: "block", Source: "10.0.20.0/24", Destination: "10.0.10.0/24"},
	}}
	text, isErr := serverWithOpnsenseStub(stub).DispatchToolForTest(context.Background(), "opnsense_list_firewall_rules", map[string]interface{}{
		"host": "fw.local", "api_key": "key1", "api_secret": "secret1",
	})
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, `"action": "block"`) || !strings.Contains(text, `"source": "10.0.20.0/24"`) {
		t.Errorf("expected rules JSON, got: %s", text)
	}
}

func TestDispatchOpnsenseListClients(t *testing.T) {
	stub := &stubOpnsenseSvc{clients: []service.OpnsenseClient{
		{MAC: "aa:bb:cc:dd:ee:ff", IP: "10.0.10.5", Hostname: "nas"},
	}}
	text, isErr := serverWithOpnsenseStub(stub).DispatchToolForTest(context.Background(), "opnsense_list_clients", map[string]interface{}{
		"host": "fw.local", "api_key": "key1", "api_secret": "secret1",
	})
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, `"hostname": "nas"`) {
		t.Errorf("expected clients JSON, got: %s", text)
	}
}

func TestDispatchOpnsenseListServicesAndGateways(t *testing.T) {
	stub := &stubOpnsenseSvc{
		services: []service.OpnsenseServiceStatus{{Name: "dnsmasq", Running: true}},
		gateways: []service.OpnsenseGatewayStatus{{Name: "WAN_DHCP", Status: "none"}},
	}
	text, isErr := serverWithOpnsenseStub(stub).DispatchToolForTest(context.Background(), "opnsense_list_services", map[string]interface{}{
		"host": "fw.local", "api_key": "key1", "api_secret": "secret1",
	})
	if isErr || !strings.Contains(text, `"name": "dnsmasq"`) || !strings.Contains(text, `"running": true`) {
		t.Fatalf("services = (%q, %v)", text, isErr)
	}
	text, isErr = serverWithOpnsenseStub(stub).DispatchToolForTest(context.Background(), "opnsense_list_gateways", map[string]interface{}{
		"host": "fw.local", "api_key": "key1", "api_secret": "secret1",
	})
	if isErr || !strings.Contains(text, `"name": "WAN_DHCP"`) {
		t.Fatalf("gateways = (%q, %v)", text, isErr)
	}
	errStub := &stubOpnsenseSvc{err: errors.New("fetch failed")}
	text, isErr = serverWithOpnsenseStub(errStub).DispatchToolForTest(context.Background(), "opnsense_list_services", map[string]interface{}{
		"host": "fw.local", "api_key": "key1", "api_secret": "secret1",
	})
	if !isErr || !strings.Contains(text, "opnsense services request failed") {
		t.Errorf("services err = (%q, %v)", text, isErr)
	}
	text, isErr = serverWithOpnsenseStub(errStub).DispatchToolForTest(context.Background(), "opnsense_list_gateways", map[string]interface{}{
		"host": "fw.local", "api_key": "key1", "api_secret": "secret1",
	})
	if !isErr || !strings.Contains(text, "opnsense gateways request failed") {
		t.Errorf("gateways err = (%q, %v)", text, isErr)
	}
}

func TestDispatchOpnsenseInventory(t *testing.T) {
	stub := &stubOpnsenseSvc{inventory: &service.OpnsenseInventory{
		Host:              "fw.local",
		ControllerVersion: "24.7.11_2",
		Arch:              "amd64",
		NetworkGateways:   map[string]string{"lan": "10.0.10.1"},
		FirewallRuleCount: 3,
		FirewallRulesOK:   true,
		ClientCount:       2,
	}}
	text, isErr := serverWithOpnsenseStub(stub).DispatchToolForTest(context.Background(), "opnsense_inventory", map[string]interface{}{
		"host": "fw.local", "api_key": "key1", "api_secret": "secret1",
	})
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, `"controller_version": "24.7.11_2"`) ||
		!strings.Contains(text, `"client_count": 2`) ||
		!strings.Contains(text, `"firewall_rule_count": 3`) ||
		!strings.Contains(text, `"network_gateways"`) {
		t.Errorf("expected inventory JSON, got: %s", text)
	}
	if strings.Contains(text, "secret1") {
		t.Error("tool output must not echo the API secret")
	}
}

func TestDispatchOpnsense_ServiceError(t *testing.T) {
	stub := &stubOpnsenseSvc{err: errors.New("fetch failed")}
	text, isErr := serverWithOpnsenseStub(stub).DispatchToolForTest(context.Background(), "opnsense_list_interfaces", map[string]interface{}{
		"host": "fw.local", "api_key": "key1", "api_secret": "secret1",
	})
	if !isErr || !strings.Contains(text, "opnsense interfaces request failed") {
		t.Errorf("got (%q, %v)", text, isErr)
	}
	if strings.Contains(text, "secret1") {
		t.Error("error output must not echo the API secret")
	}
}

// TestOpnsenseNatRequestFromArgs — argument validation and mapping for the
// opnsense_plan_nat / opnsense_apply_nat tools.
func TestOpnsenseNatRequestFromArgs(t *testing.T) {
	cases := []struct {
		name    string
		args    map[string]interface{}
		wantErr string
	}{
		{"missing operation", map[string]interface{}{"host": "fw.local"}, "operation parameter is required"},
		{"update missing rule_uuid", map[string]interface{}{"operation": "port_forward", "action": "update"}, "rule_uuid is required"},
		{"delete missing rule_uuid", map[string]interface{}{"operation": "one_to_one", "action": "delete"}, "rule_uuid is required"},
		{"toggle missing rule_uuid", map[string]interface{}{"operation": "source_nat", "action": "toggle"}, "rule_uuid is required"},
		{"default action is create", map[string]interface{}{"operation": "port_forward"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, msg := opnsenseNatRequestFromArgs(tc.args)
			if tc.wantErr == "" {
				if msg != "" {
					t.Fatalf("msg = %q, want none", msg)
				}
				return
			}
			if !strings.Contains(msg, tc.wantErr) {
				t.Fatalf("msg = %q, want containing %q", msg, tc.wantErr)
			}
			_ = req
		})
	}

	// Full argument mapping: every spec field lands on the service request.
	req, msg := opnsenseNatRequestFromArgs(map[string]interface{}{
		"operation":        "port_forward",
		"action":           "update",
		"rule_uuid":        "u-1",
		"interfaces":       "lan,wan",
		"protocol":         "tcp",
		"source":           "10.0.40.0/24",
		"destination":      "10.0.40.10",
		"port":             "443",
		"local_port":       "8443",
		"target":           "10.0.40.20",
		"type":             "binat",
		"label":            "web",
		"toggle_disable":   true,
		"allow_double_nat": true,
		"dry_run":          false,
	})
	if msg != "" {
		t.Fatalf("msg = %q, want none", msg)
	}
	if req.Operation != "port_forward" || req.Action != "update" || req.RuleUUID != "u-1" {
		t.Errorf("req = %+v", req)
	}
	if len(req.Spec.Interfaces) != 2 || req.Spec.Interfaces[0] != "lan" || req.Spec.Interfaces[1] != "wan" {
		t.Errorf("interfaces = %v, want [lan wan]", req.Spec.Interfaces)
	}
	if req.Spec.Protocol != "tcp" || req.Spec.Source != "10.0.40.0/24" || req.Spec.Destination != "10.0.40.10" ||
		req.Spec.Port != "443" || req.Spec.LocalPort != "8443" || req.Spec.Target != "10.0.40.20" ||
		req.Spec.Type != "binat" || req.Spec.Label != "web" {
		t.Errorf("spec = %+v", req.Spec)
	}
	if !req.ToggleDisable || !req.AllowDoubleNat || req.DryRun {
		t.Errorf("flags = %v/%v/%v, want true/true/false", req.ToggleDisable, req.AllowDoubleNat, req.DryRun)
	}

	// dry_run defaults to true (the MCP-layer dry-run lock).
	req, _ = opnsenseNatRequestFromArgs(map[string]interface{}{"operation": "port_forward"})
	if !req.DryRun {
		t.Error("dry_run must default to true at the MCP layer")
	}
}

func TestDispatchOpnsensePlanNat(t *testing.T) {
	hermeticCreds(t)
	stub := &stubOpnsenseSvc{
		planResult: &providers.NatPlan{
			Provider:  "opnsense",
			DryRun:    true,
			Outcome:   "would_create",
			Endpoints: []string{"/firewall/d_nat/add_rule"},
			Before:    "[]",
		},
	}
	text, isErr := serverWithOpnsenseStub(stub).DispatchToolForTest(context.Background(), "opnsense_plan_nat", map[string]interface{}{
		"host": "fw.local", "api_key": "key1", "api_secret": "secret1",
		"operation": "port_forward",
	})
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, `"outcome": "would_create"`) || !strings.Contains(text, `"dry_run": true`) {
		t.Errorf("plan JSON = %s", text)
	}
	if strings.Contains(text, "secret1") {
		t.Error("tool output must not echo the API secret")
	}
}

func TestDispatchOpnsenseApplyNat(t *testing.T) {
	hermeticCreds(t)
	stub := &stubOpnsenseSvc{
		applyResult: &providers.NatApplyResult{
			Provider:  "opnsense",
			Outcome:   "created",
			RuleUUID:  "new-1",
			Endpoints: []string{"/firewall/d_nat/add_rule"},
		},
	}
	text, isErr := serverWithOpnsenseStub(stub).DispatchToolForTest(context.Background(), "opnsense_apply_nat", map[string]interface{}{
		"host": "fw.local", "api_key": "key1", "api_secret": "secret1",
		"operation":   "port_forward",
		"interfaces":  "lan",
		"destination": "10.0.40.10",
		"port":        "443",
		"target":      "10.0.40.20",
		"dry_run":     false,
	})
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if !strings.Contains(text, `"outcome": "created"`) || !strings.Contains(text, `"rule_uuid": "new-1"`) {
		t.Errorf("apply JSON = %s", text)
	}
	// The mapped request carries the spec fields and the explicit dry_run.
	got := stub.lastApplyReq
	if got.Spec.Destination != "10.0.40.10" || got.Spec.Port != "443" || got.Spec.Target != "10.0.40.20" {
		t.Errorf("mapped spec = %+v", got.Spec)
	}
	if got.DryRun {
		t.Error("dry_run = true, want false (explicit false must not be flipped)")
	}
	if strings.Contains(text, "secret1") {
		t.Error("tool output must not echo the API secret")
	}
}

func TestDispatchOpnsenseNat_Errors(t *testing.T) {
	hermeticCreds(t)

	// Argument validation errors surface before any service call.
	stub := &stubOpnsenseSvc{}
	text, isErr := serverWithOpnsenseStub(stub).DispatchToolForTest(context.Background(), "opnsense_plan_nat", map[string]interface{}{
		"host": "fw.local", "api_key": "key1", "api_secret": "secret1",
	})
	if !isErr || !strings.Contains(text, "operation parameter is required") {
		t.Errorf("plan args: got (%q, %v)", text, isErr)
	}
	text, isErr = serverWithOpnsenseStub(stub).DispatchToolForTest(context.Background(), "opnsense_apply_nat", map[string]interface{}{
		"host": "fw.local", "api_key": "key1", "api_secret": "secret1",
		"operation": "port_forward",
		"action":    "update",
	})
	if !isErr || !strings.Contains(text, "rule_uuid is required for action") {
		t.Errorf("apply args: got (%q, %v)", text, isErr)
	}

	// Service errors wrap the tool name, not the credentials.
	stubErr := &stubOpnsenseSvc{err: errors.New("controller down")}
	for _, tool := range []string{"opnsense_plan_nat", "opnsense_apply_nat"} {
		t.Run(tool, func(t *testing.T) {
			text, isErr := serverWithOpnsenseStub(stubErr).DispatchToolForTest(context.Background(), tool, map[string]interface{}{
				"host": "fw.local", "api_key": "key1", "api_secret": "secret1",
				"operation": "port_forward",
			})
			if !isErr || !strings.Contains(text, "request failed") || !strings.Contains(text, "controller down") {
				t.Errorf("got (%q, %v), want service error", text, isErr)
			}
			if strings.Contains(text, "secret1") {
				t.Error("error output must not echo the API secret")
			}
		})
	}
}

func nonEmptyLines(s string) []string {
	var lines []string
	for _, l := range strings.Split(s, "\n") {
		if l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

// failingReader returns an error on the first read to exercise scanner error propagation.
type failingReader struct{}

func (f *failingReader) Read([]byte) (int, error) {
	return 0, os.ErrClosed
}

// errBackend fails all route/interface/health lookups so dispatch error branches run hermetically.
type errBackend struct {
	backends.Backend
}

func (e errBackend) Ping(ctx context.Context, target string) (*system.PingResult, error) {
	return nil, errors.New("ping unavailable")
}

func (e errBackend) GetRouteToTarget(ctx context.Context, target string) (*system.Route, error) {
	return nil, errors.New("route unavailable")
}

func (e errBackend) GetInterfaces(ctx context.Context) ([]system.Interface, error) {
	return nil, errors.New("no interfaces")
}

func (e errBackend) CheckVPNInterface(ctx context.Context, device string) (bool, error) {
	return false, errors.New("vpn unavailable")
}

// dummyProvider satisfies the Provider interface for registry tests.
type dummyProvider struct{}

func (d *dummyProvider) Name() string           { return "dummy" }
func (d *dummyProvider) Capabilities() []string { return []string{"info"} }
func (d *dummyProvider) Info(context.Context, providers.ImportOptions) (*providers.ProviderInfo, error) {
	return nil, errors.New("unused")
}
func (d *dummyProvider) ImportSpec(context.Context, providers.ImportOptions) (*providers.ImportResult, error) {
	return nil, errors.New("unused")
}
func (d *dummyProvider) Check(context.Context, providers.ImportOptions) (*providers.AuditResult, error) {
	return nil, errors.New("unused")
}
func (d *dummyProvider) CheckACL(ctx context.Context, req providers.ACLCheckRequest, opts providers.ImportOptions) (*models.CheckResult, error) {
	return nil, errors.New("unused")
}
func (d *dummyProvider) Spec() *intent.Spec { return nil }

// blockingOmadaSvc blocks until the context is cancelled, simulating a hung
// backend that observes cancellation but takes longer than the tool timeout.
type blockingOmadaSvc struct {
	stubOmadaSvc
	started chan struct{}
}

func (b *blockingOmadaSvc) Info(ctx context.Context, _ service.OmadaOptions) (*service.OmadaInfo, error) {
	close(b.started)
	<-ctx.Done()
	return nil, ctx.Err()
}

// stubOmadaSvc is a hermetic stand-in for the Omada observation surface.
type stubOmadaSvc struct {
	info          *service.OmadaInfo
	networks      []service.OmadaNetwork
	acls          []service.OmadaACLRule
	clients       []service.OmadaClient
	inventory     *service.OmadaInventory
	imp           *service.OmadaImport
	plan          *service.OmadaPlan
	apply         *service.OmadaACLApplyResult
	portFwd       []service.OmadaPortForwarding
	oneToOne      []service.OmadaOneToOneNAT
	alg           *service.OmadaALGSettings
	firewall      *service.OmadaFirewallSettings
	natFacts      *service.OmadaNatFacts
	uplink        []service.OmadaUplinkInfo
	switchPorts   []service.OmadaSwitchPort
	profiles      []service.OmadaLanProfile
	portPlan      *service.OmadaPortPlan
	portApply     *service.OmadaPortProfileApplyResult
	err           error
	lastOpts      service.OmadaOptions
	lastApplyReq  service.OmadaACLApplyRequest
	lastMACs      []string
	lastPortReq   service.OmadaPortProfileRequest
	lastDryRun    bool
	calls         int
	dhcpUsers     []service.OmadaGatewayDHCPUser
	lastGWMAC     string
	topoNodes     []service.OmadaClientTopologyNode
	lastClientMAC string
}

func (s *stubOmadaSvc) Info(_ context.Context, opts service.OmadaOptions) (*service.OmadaInfo, error) {
	s.calls++
	s.lastOpts = opts
	return s.info, s.err
}

func (s *stubOmadaSvc) ListNetworks(_ context.Context, opts service.OmadaOptions) ([]service.OmadaNetwork, error) {
	s.calls++
	s.lastOpts = opts
	return s.networks, s.err
}

func (s *stubOmadaSvc) ListACLs(_ context.Context, opts service.OmadaOptions) ([]service.OmadaACLRule, error) {
	s.calls++
	s.lastOpts = opts
	return s.acls, s.err
}

func (s *stubOmadaSvc) ListClients(_ context.Context, opts service.OmadaOptions) ([]service.OmadaClient, error) {
	s.calls++
	s.lastOpts = opts
	return s.clients, s.err
}

func (s *stubOmadaSvc) Inventory(_ context.Context, opts service.OmadaOptions) (*service.OmadaInventory, error) {
	s.calls++
	s.lastOpts = opts
	return s.inventory, s.err
}

func (s *stubOmadaSvc) Import(_ context.Context, opts service.OmadaOptions) (*service.OmadaImport, error) {
	s.calls++
	s.lastOpts = opts
	return s.imp, s.err
}

func (s *stubOmadaSvc) Plan(_ context.Context, opts service.OmadaOptions, _ string) (*service.OmadaPlan, error) {
	s.calls++
	s.lastOpts = opts
	return s.plan, s.err
}

func (s *stubOmadaSvc) ApplyACL(_ context.Context, opts service.OmadaOptions, req service.OmadaACLApplyRequest) (*service.OmadaACLApplyResult, error) {
	s.calls++
	s.lastOpts = opts
	s.lastApplyReq = req
	return s.apply, s.err
}

func (s *stubOmadaSvc) ListPortForwardings(_ context.Context, opts service.OmadaOptions) ([]service.OmadaPortForwarding, error) {
	s.calls++
	s.lastOpts = opts
	return s.portFwd, s.err
}

func (s *stubOmadaSvc) ListOneToOneNAT(_ context.Context, opts service.OmadaOptions) ([]service.OmadaOneToOneNAT, error) {
	s.calls++
	s.lastOpts = opts
	return s.oneToOne, s.err
}

func (s *stubOmadaSvc) GetALGSettings(_ context.Context, opts service.OmadaOptions) (*service.OmadaALGSettings, error) {
	s.calls++
	s.lastOpts = opts
	return s.alg, s.err
}

func (s *stubOmadaSvc) GetFirewallSettings(_ context.Context, opts service.OmadaOptions) (*service.OmadaFirewallSettings, error) {
	s.calls++
	s.lastOpts = opts
	return s.firewall, s.err
}

func (s *stubOmadaSvc) NatFacts(_ context.Context, opts service.OmadaOptions) (*service.OmadaNatFacts, error) {
	s.calls++
	s.lastOpts = opts
	return s.natFacts, s.err
}

func (s *stubOmadaSvc) GetUplinkInfo(_ context.Context, opts service.OmadaOptions, macs []string) ([]service.OmadaUplinkInfo, error) {
	s.calls++
	s.lastOpts = opts
	s.lastMACs = macs
	return s.uplink, s.err
}

func (s *stubOmadaSvc) ListSwitchPorts(_ context.Context, opts service.OmadaOptions, _ string) ([]service.OmadaSwitchPort, error) {
	s.calls++
	s.lastOpts = opts
	return s.switchPorts, s.err
}

func (s *stubOmadaSvc) ListGatewayDHCPUsers(_ context.Context, opts service.OmadaOptions, gatewayMAC string) ([]service.OmadaGatewayDHCPUser, error) {
	s.calls++
	s.lastOpts = opts
	s.lastGWMAC = gatewayMAC
	return s.dhcpUsers, s.err
}

func (s *stubOmadaSvc) GetClientTopology(_ context.Context, opts service.OmadaOptions, clientMAC string) ([]service.OmadaClientTopologyNode, error) {
	s.calls++
	s.lastOpts = opts
	s.lastClientMAC = clientMAC
	return s.topoNodes, s.err
}

func (s *stubOmadaSvc) ListLanProfiles(_ context.Context, opts service.OmadaOptions) ([]service.OmadaLanProfile, error) {
	s.calls++
	s.lastOpts = opts
	return s.profiles, s.err
}

func (s *stubOmadaSvc) PlanPort(_ context.Context, opts service.OmadaOptions, req service.OmadaPortProfileRequest) (*service.OmadaPortPlan, error) {
	s.calls++
	s.lastOpts = opts
	s.lastPortReq = req
	return s.portPlan, s.err
}

func (s *stubOmadaSvc) ApplyPortProfile(_ context.Context, opts service.OmadaOptions, req service.OmadaPortProfileRequest, dryRun bool) (*service.OmadaPortProfileApplyResult, error) {
	s.calls++
	s.lastOpts = opts
	s.lastPortReq = req
	s.lastDryRun = dryRun
	if s.portApply == nil {
		return nil, s.err // error path: the result is never built
	}
	res := *s.portApply
	res.DryRun = dryRun // mirror the arg so handlers can be asserted on the wire
	return &res, s.err
}

func sliceEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sliceEqInt(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// stubOpnsenseSvc is a hermetic stand-in for the OPNsense observation surface.
type stubOpnsenseSvc struct {
	info         *service.OpnsenseInfo
	interfaces   []service.OpnsenseInterface
	rules        []service.OpnsenseFirewallRule
	clients      []service.OpnsenseClient
	portFwd      []service.OpnsenseNatRule
	oneToOne     []service.OpnsenseNatRule
	sourceNat    []service.OpnsenseNatRule
	aliases      []service.OpnsenseAlias
	services     []service.OpnsenseServiceStatus
	gateways     []service.OpnsenseGatewayStatus
	natMode      string
	natSummary   *service.OpnsenseNatSummary
	inventory    *service.OpnsenseInventory
	planResult   *providers.NatPlan
	applyResult  *providers.NatApplyResult
	lastApplyReq service.OpnsenseNatApplyRequest
	err          error
	lastOpts     service.OpnsenseOptions
}

func (s *stubOpnsenseSvc) Info(_ context.Context, opts service.OpnsenseOptions) (*service.OpnsenseInfo, error) {
	s.lastOpts = opts
	return s.info, s.err
}

func (s *stubOpnsenseSvc) ListInterfaces(_ context.Context, opts service.OpnsenseOptions) ([]service.OpnsenseInterface, error) {
	s.lastOpts = opts
	return s.interfaces, s.err
}

func (s *stubOpnsenseSvc) ListFirewallRules(_ context.Context, opts service.OpnsenseOptions) ([]service.OpnsenseFirewallRule, error) {
	s.lastOpts = opts
	return s.rules, s.err
}

func (s *stubOpnsenseSvc) ListClients(_ context.Context, opts service.OpnsenseOptions) ([]service.OpnsenseClient, error) {
	s.lastOpts = opts
	return s.clients, s.err
}

func (s *stubOpnsenseSvc) ListPortForwardRules(_ context.Context, opts service.OpnsenseOptions) ([]service.OpnsenseNatRule, error) {
	s.lastOpts = opts
	return s.portFwd, s.err
}

func (s *stubOpnsenseSvc) ListOneToOneRules(_ context.Context, opts service.OpnsenseOptions) ([]service.OpnsenseNatRule, error) {
	s.lastOpts = opts
	return s.oneToOne, s.err
}

func (s *stubOpnsenseSvc) ListSourceNatRules(_ context.Context, opts service.OpnsenseOptions) ([]service.OpnsenseNatRule, error) {
	s.lastOpts = opts
	return s.sourceNat, s.err
}

func (s *stubOpnsenseSvc) ListAliases(_ context.Context, opts service.OpnsenseOptions) ([]service.OpnsenseAlias, error) {
	s.lastOpts = opts
	return s.aliases, s.err
}

func (s *stubOpnsenseSvc) ListServices(_ context.Context, opts service.OpnsenseOptions) ([]service.OpnsenseServiceStatus, error) {
	s.lastOpts = opts
	return s.services, s.err
}

func (s *stubOpnsenseSvc) ListGateways(_ context.Context, opts service.OpnsenseOptions) ([]service.OpnsenseGatewayStatus, error) {
	s.lastOpts = opts
	return s.gateways, s.err
}

func (s *stubOpnsenseSvc) GetOutboundNatMode(_ context.Context, opts service.OpnsenseOptions) (string, error) {
	s.lastOpts = opts
	return s.natMode, s.err
}

func (s *stubOpnsenseSvc) GetNAT(_ context.Context, opts service.OpnsenseOptions) (*service.OpnsenseNatSummary, error) {
	s.lastOpts = opts
	return s.natSummary, s.err
}

func (s *stubOpnsenseSvc) Inventory(_ context.Context, opts service.OpnsenseOptions) (*service.OpnsenseInventory, error) {
	s.lastOpts = opts
	return s.inventory, s.err
}

func (s *stubOpnsenseSvc) PlanNat(_ context.Context, opts service.OpnsenseOptions, _ service.OpnsenseNatApplyRequest) (*providers.NatPlan, error) {
	s.lastOpts = opts
	return s.planResult, s.err
}

func (s *stubOpnsenseSvc) ApplyNat(_ context.Context, opts service.OpnsenseOptions, req service.OpnsenseNatApplyRequest) (*providers.NatApplyResult, error) {
	s.lastOpts = opts
	s.lastApplyReq = req
	return s.applyResult, s.err
}

// stubTopoSvc is a hermetic stand-in for the cross-provider topology report.
type stubTopoSvc struct {
	report *service.TopologyReport
	err    error
	opts   service.TopologyOptions
	calls  int
}

func (s *stubTopoSvc) Report(_ context.Context, opts service.TopologyOptions) (*service.TopologyReport, error) {
	s.calls++
	s.opts = opts
	return s.report, s.err
}

func serverWithOpnsenseStub(stub *stubOpnsenseSvc) *Server {
	omada, opnsense := credEnvReaders()
	return &Server{
		reader:          &bytes.Buffer{},
		writer:          &bytes.Buffer{},
		checkSvc:        service.NewCheckService(),
		opnsenseSvc:     stub,
		topoSvc:         &stubTopoSvc{},
		credEnv:         omada,
		opnsenseCredEnv: opnsense,
	}
}

func serverWithOmadaStub(stub *stubOmadaSvc) *Server {
	omada, opnsense := credEnvReaders()
	return &Server{
		reader:          &bytes.Buffer{},
		writer:          &bytes.Buffer{},
		checkSvc:        service.NewCheckService(),
		omadaSvc:        stub,
		topoSvc:         &stubTopoSvc{},
		credEnv:         omada,
		opnsenseCredEnv: opnsense,
	}
}

func TestDispatchOmadaNatReads(t *testing.T) {
	stub := &stubOmadaSvc{
		portFwd:  []service.OmadaPortForwarding{{ID: "pf1", Name: "web", ExternalPort: "443", ForwardPort: "80", Protocol: "TCP"}},
		oneToOne: []service.OmadaOneToOneNAT{{ID: "o1", Name: "binat", ExternalIP: "203.0.113.20"}},
		alg:      &service.OmadaALGSettings{FTP: true, SIP: true},
		firewall: &service.OmadaFirewallSettings{ICMP: 30, SynCookies: true},
		natFacts: &service.OmadaNatFacts{Site: "HQ", HasManagedGateway: true, PortForwardRules: 1, OneToOneRules: 1},
	}
	server := serverWithOmadaStub(stub)
	args := map[string]interface{}{"host": "omada.local", "client_id": "cid-1", "client_secret": "pw", "site": "HQ"}

	if text, isErr := server.DispatchToolForTest(context.Background(), "omada_list_port_forwardings", args); isErr {
		t.Fatalf("port forwardings: unexpected error: %s", text)
	} else if !strings.Contains(text, `"name": "web"`) || !strings.Contains(text, `"protocol": "TCP"`) {
		t.Errorf("port forwardings JSON = %s", text)
	}
	if text, isErr := server.DispatchToolForTest(context.Background(), "omada_list_one_to_one_nat", args); isErr {
		t.Fatalf("one-to-one: unexpected error: %s", text)
	} else if !strings.Contains(text, `"external_ip": "203.0.113.20"`) {
		t.Errorf("one-to-one JSON = %s", text)
	}
	if text, isErr := server.DispatchToolForTest(context.Background(), "omada_get_nat_settings", args); isErr {
		t.Fatalf("nat settings: unexpected error: %s", text)
	} else if !strings.Contains(text, `"ftp": true`) || !strings.Contains(text, `"icmp": 30`) {
		t.Errorf("nat settings JSON = %s", text)
	}
	if text, isErr := server.DispatchToolForTest(context.Background(), "omada_nat_facts", args); isErr {
		t.Fatalf("nat facts: unexpected error: %s", text)
	} else if !strings.Contains(text, `"has_managed_gateway": true`) {
		t.Errorf("nat facts JSON = %s", text)
	}
	if stub.lastOpts.Host != "omada.local" || stub.lastOpts.Site != "HQ" {
		t.Errorf("options = %+v", stub.lastOpts)
	}
}

func TestDispatchOmadaNatReads_ServiceError(t *testing.T) {
	server := serverWithOmadaStub(&stubOmadaSvc{err: errors.New("site not found")})
	text, isErr := server.DispatchToolForTest(context.Background(), "omada_nat_facts", map[string]interface{}{
		"host": "omada.local", "client_id": "cid-1", "client_secret": "pw",
	})
	if !isErr || !strings.Contains(text, "omada nat facts request failed") || !strings.Contains(text, "site not found") {
		t.Errorf("got (%q, %v)", text, isErr)
	}
}

func TestDispatchOmadaPortReads(t *testing.T) {
	// Redirect the credential store away from the real one so the inline
	// test credentials below are the only source of truth (hermetic on any
	// runner, even one with an existing omada/default entry).
	t.Setenv("NYX_CREDENTIALS_FILE", t.TempDir()+"/credentials.json")
	// One stub per assertion so a single stub can't leak state across cases.
	uplinkStub := &stubOmadaSvc{
		uplink: []service.OmadaUplinkInfo{{MAC: "aa:bb:cc:dd:ee:01", UplinkDeviceMAC: "aa:bb:cc:dd:ee:00", UplinkDevicePort: "8"}},
	}
	if text, isErr := serverWithOmadaStub(uplinkStub).DispatchToolForTest(context.Background(), "omada_get_uplink_info",
		map[string]interface{}{"host": "omada.local", "client_id": "cid-1", "client_secret": "pw", "device_mac": "aa:bb:cc:dd:ee:01"}); isErr {
		t.Fatalf("uplink: unexpected error: %s", text)
	} else if !strings.Contains(text, `"uplink_device_port": "8"`) {
		t.Errorf("uplink JSON = %s", text)
	} else if len(uplinkStub.lastMACs) != 1 || uplinkStub.lastMACs[0] != "aa:bb:cc:dd:ee:01" {
		t.Errorf("uplink macs = %v, want [aa:bb:cc:dd:ee:01]", uplinkStub.lastMACs)
	}

	// No observed uplink → explicit note, not a bare empty array.
	if text, isErr := serverWithOmadaStub(&stubOmadaSvc{}).DispatchToolForTest(context.Background(), "omada_get_uplink_info",
		map[string]interface{}{"host": "omada.local", "client_id": "cid-1", "client_secret": "pw", "device_mac": "no:such:mac"}); isErr {
		t.Fatalf("uplink empty: unexpected error: %s", text)
	} else if !strings.Contains(text, "no uplink observed") {
		t.Errorf("uplink empty note = %s", text)
	}

	// Missing device_mac.
	if text, isErr := serverWithOmadaStub(&stubOmadaSvc{}).DispatchToolForTest(context.Background(), "omada_get_uplink_info",
		map[string]interface{}{"host": "omada.local", "client_id": "cid-1", "client_secret": "pw"}); !isErr || !strings.Contains(text, "device_mac parameter is required") {
		t.Errorf("uplink missing mac: got (%q, %v)", text, isErr)
	}

	if text, isErr := serverWithOmadaStub(&stubOmadaSvc{
		switchPorts: []service.OmadaSwitchPort{{Port: 8, SwitchMAC: "aa:bb:cc:dd:ee:00", NativeNetwork: "trusted", Tagged: []string{"gaming", "media"}}},
	}).DispatchToolForTest(context.Background(), "omada_list_switch_ports",
		map[string]interface{}{"host": "omada.local", "client_id": "cid-1", "client_secret": "pw", "switch_mac": "aa:bb:cc:dd:ee:00"}); isErr {
		t.Fatalf("switch ports: unexpected error: %s", text)
	} else if !strings.Contains(text, `"native_network": "trusted"`) || !strings.Contains(text, `"gaming"`) {
		t.Errorf("switch ports JSON = %s", text)
	}

	if text, isErr := serverWithOmadaStub(&stubOmadaSvc{
		profiles: []service.OmadaLanProfile{{ID: "lp1", Name: "trunk", NativeNetwork: "trusted", TaggedNetworks: []string{"gaming", "media"}}},
	}).DispatchToolForTest(context.Background(), "omada_list_lan_profiles",
		map[string]interface{}{"host": "omada.local", "client_id": "cid-1", "client_secret": "pw"}); isErr {
		t.Fatalf("lan profiles: unexpected error: %s", text)
	} else if !strings.Contains(text, `"name": "trunk"`) {
		t.Errorf("lan profiles JSON = %s", text)
	}

	planArgs := map[string]interface{}{"host": "omada.local", "client_id": "cid-1", "client_secret": "pw", "switch_mac": "aa:bb:cc:dd:ee:00", "port": float64(8), "native": "trusted", "tagged": "gaming,media"}
	planStub := &stubOmadaSvc{portPlan: &service.OmadaPortPlan{SwitchMAC: "aa:bb:cc:dd:ee:00", Port: 8, Outcome: "rebind", ProfileID: "lp1"}}
	if text, isErr := serverWithOmadaStub(planStub).DispatchToolForTest(context.Background(), "omada_plan_port", planArgs); isErr {
		t.Fatalf("plan port: unexpected error: %s", text)
	} else if !strings.Contains(text, `"outcome": "rebind"`) {
		t.Errorf("plan port JSON = %s", text)
	}
	// The request arguments reach the service verbatim.
	if planStub.lastPortReq.SwitchMAC != "aa:bb:cc:dd:ee:00" || planStub.lastPortReq.Port != 8 ||
		planStub.lastPortReq.Native != "trusted" || len(planStub.lastPortReq.Tagged) != 2 {
		t.Errorf("request = %+v", planStub.lastPortReq)
	}

	// Dry-run is the default: an omitted dry_run applies the true default.
	applyStub := &stubOmadaSvc{portApply: &service.OmadaPortProfileApplyResult{Outcome: "rebind", ProfileID: "lp1", Before: "{}", After: "{}"}}
	if text, isErr := serverWithOmadaStub(applyStub).DispatchToolForTest(context.Background(), "omada_apply_port_profile", planArgs); isErr {
		t.Fatalf("apply port: unexpected error: %s", text)
	} else if !strings.Contains(text, `"dry_run": true`) {
		t.Errorf("apply port JSON = %s", text)
	} else if !applyStub.lastDryRun {
		t.Error("apply port: dry_run default should reach the service as true")
	}

	// An explicit dry_run=false reaches the service and is echoed back.
	applyStub2 := &stubOmadaSvc{portApply: &service.OmadaPortProfileApplyResult{Outcome: "created_and_bound", ProfileID: "lp2"}}
	realArgs := map[string]interface{}{"host": "omada.local", "client_id": "cid-1", "client_secret": "pw", "switch_mac": "aa:bb:cc:dd:ee:00", "port": float64(8), "native": "trusted", "dry_run": false}
	if text, isErr := serverWithOmadaStub(applyStub2).DispatchToolForTest(context.Background(), "omada_apply_port_profile", realArgs); isErr {
		t.Fatalf("apply port real: unexpected error: %s", text)
	} else if !strings.Contains(text, `"dry_run": false`) || !strings.Contains(text, `"outcome": "created_and_bound"`) {
		t.Errorf("apply port real JSON = %s", text)
	} else if applyStub2.lastDryRun {
		t.Error("apply port: dry_run=false should reach the service as false")
	}

	if text, isErr := serverWithOmadaStub(&stubOmadaSvc{}).DispatchToolForTest(context.Background(), "omada_plan_port",
		map[string]interface{}{"host": "omada.local", "client_id": "cid-1", "client_secret": "pw", "switch_mac": "aa:bb:cc:dd:ee:00", "native": "trusted"}); !isErr || !strings.Contains(text, "port parameter is required") {
		t.Errorf("plan port missing port: got (%q, %v)", text, isErr)
	}

	if text, isErr := serverWithOmadaStub(&stubOmadaSvc{}).DispatchToolForTest(context.Background(), "omada_plan_port",
		map[string]interface{}{"host": "omada.local", "client_id": "cid-1", "client_secret": "pw", "port": float64(8), "native": "trusted"}); !isErr || !strings.Contains(text, "switch_mac parameter is required") {
		t.Errorf("plan port missing mac: got (%q, %v)", text, isErr)
	}

	if text, isErr := serverWithOmadaStub(&stubOmadaSvc{}).DispatchToolForTest(context.Background(), "omada_apply_port_profile",
		map[string]interface{}{"host": "omada.local", "client_id": "cid-1", "client_secret": "pw", "switch_mac": "aa:bb:cc:dd:ee:00", "port": float64(8)}); !isErr || !strings.Contains(text, "native parameter is required") {
		t.Errorf("apply port missing native: got (%q, %v)", text, isErr)
	}
}

func TestDispatchOmadaPortReads_ServiceError(t *testing.T) {
	t.Setenv("NYX_CREDENTIALS_FILE", t.TempDir()+"/credentials.json")
	server := serverWithOmadaStub(&stubOmadaSvc{err: errors.New("site not found")})
	args := map[string]interface{}{"host": "omada.local", "client_id": "cid-1", "client_secret": "pw", "switch_mac": "aa:bb:cc:dd:ee:00", "port": float64(8), "native": "trusted"}
	if text, isErr := server.DispatchToolForTest(context.Background(), "omada_plan_port", args); !isErr || !strings.Contains(text, "omada port plan request failed") {
		t.Errorf("plan: got (%q, %v)", text, isErr)
	}
	if text, isErr := server.DispatchToolForTest(context.Background(), "omada_apply_port_profile", args); !isErr || !strings.Contains(text, "omada port profile apply failed") {
		t.Errorf("apply: got (%q, %v)", text, isErr)
	}
}

func TestDispatchOpnsenseNatReads(t *testing.T) {
	stub := &stubOpnsenseSvc{
		portFwd:   []service.OpnsenseNatRule{{UUID: "n1", Protocol: "tcp", Source: "any", Destination: "10.0.40.0/24"}},
		oneToOne:  []service.OpnsenseNatRule{{UUID: "o1", Mode: "binat", Target: "10.0.10.5"}},
		sourceNat: []service.OpnsenseNatRule{{UUID: "s1", Target: "203.0.113.100", SNATMode: "one-to-one"}},
		aliases:   []service.OpnsenseAlias{{Name: "trusted", Addresses: []string{"10.0.10.0/24"}}},
		natSummary: &service.OpnsenseNatSummary{
			OutboundNatMode:  "disabled",
			PortForwardRules: []service.OpnsenseNatRule{{UUID: "n1"}},
			SourceNatRules:   []service.OpnsenseNatRule{{UUID: "s1"}},
		},
	}
	server := serverWithOpnsenseStub(stub)
	args := map[string]interface{}{"host": "fw.local", "api_key": "key1", "api_secret": "secret1"}

	if text, isErr := server.DispatchToolForTest(context.Background(), "opnsense_list_port_forward_rules", args); isErr {
		t.Fatalf("port forward rules: unexpected error: %s", text)
	} else if !strings.Contains(text, `"uuid": "n1"`) || !strings.Contains(text, `"destination": "10.0.40.0/24"`) {
		t.Errorf("port forward rules JSON = %s", text)
	}
	if text, isErr := server.DispatchToolForTest(context.Background(), "opnsense_list_one_to_one_rules", args); isErr {
		t.Fatalf("one-to-one rules: unexpected error: %s", text)
	} else if !strings.Contains(text, `"mode": "binat"`) {
		t.Errorf("one-to-one rules JSON = %s", text)
	}
	if text, isErr := server.DispatchToolForTest(context.Background(), "opnsense_list_source_nat_rules", args); isErr {
		t.Fatalf("source NAT rules: unexpected error: %s", text)
	} else if !strings.Contains(text, `"snat_mode": "one-to-one"`) {
		t.Errorf("source NAT rules JSON = %s", text)
	}
	if text, isErr := server.DispatchToolForTest(context.Background(), "opnsense_list_aliases", args); isErr {
		t.Fatalf("aliases: unexpected error: %s", text)
	} else if !strings.Contains(text, `"name": "trusted"`) {
		t.Errorf("aliases JSON = %s", text)
	}
	if text, isErr := server.DispatchToolForTest(context.Background(), "opnsense_get_nat", args); isErr {
		t.Fatalf("get nat: unexpected error: %s", text)
	} else if !strings.Contains(text, `"outbound_nat_mode": "disabled"`) {
		t.Errorf("get nat JSON = %s", text)
	} else if strings.Contains(text, "secret1") {
		t.Error("tool output must not echo the API secret")
	}
}

func TestDispatchOpnsenseNatReads_ServiceError(t *testing.T) {
	server := serverWithOpnsenseStub(&stubOpnsenseSvc{err: errors.New("boom")})
	text, isErr := server.DispatchToolForTest(context.Background(), "opnsense_get_nat", map[string]interface{}{
		"host": "fw.local", "api_key": "key1", "api_secret": "secret1",
	})
	if !isErr || !strings.Contains(text, "opnsense NAT posture request failed") || !strings.Contains(text, "boom") {
		t.Errorf("got (%q, %v)", text, isErr)
	}
}

func TestDispatchTopology(t *testing.T) {
	hermeticCreds(t)
	topo := &stubTopoSvc{report: &service.TopologyReport{
		Devices: []topology.DeviceReport{{Provider: "opnsense", Role: topology.RoleBridge}},
		Risk:    "none",
		Reason:  "one NAT owner",
	}}
	server := serverWithOmadaStub(&stubOmadaSvc{})
	server.topoSvc = topo
	text, isErr := server.DispatchToolForTest(context.Background(), "topology", map[string]interface{}{
		"omada_host":          "omada.local",
		"omada_client_id":     "cid-1",
		"omada_client_secret": "pw",
		"omada_site":          "HQ",
	})
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if topo.calls != 1 {
		t.Fatalf("topology calls = %d, want 1", topo.calls)
	}
	if topo.opts.Omada == nil || topo.opts.Omada.Host != "omada.local" || topo.opts.Omada.Site != "HQ" || topo.opts.Opnsense != nil {
		t.Errorf("topology options = %+v", topo.opts)
	}
	if !strings.Contains(text, `"risk": "none"`) || !strings.Contains(text, `"provider": "opnsense"`) {
		t.Errorf("report JSON = %s", text)
	}
	if strings.Contains(text, "secret") {
		t.Error("tool output must not echo credentials")
	}
}

func TestDispatchTopology_SkipsUnconfiguredProvider(t *testing.T) {
	hermeticCreds(t)
	omada, opnsense := credEnvReaders()
	topo := &stubTopoSvc{}
	server := &Server{reader: &bytes.Buffer{}, writer: &bytes.Buffer{},
		checkSvc: service.NewCheckService(), topoSvc: topo,
		credEnv: omada, opnsenseCredEnv: opnsense}
	text, isErr := server.DispatchToolForTest(context.Background(), "topology", map[string]interface{}{
		"opnsense_host": "fw.local", "opnsense_api_key": "key1", "opnsense_api_secret": "secret1",
	})
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if topo.calls != 1 || topo.opts.Opnsense == nil || topo.opts.Omada != nil {
		t.Errorf("options = %+v (omada must be skipped)", topo.opts)
	}
	_ = text
}

func TestDispatchTopology_NoProviders(t *testing.T) {
	hermeticCreds(t)
	omada, opnsense := credEnvReaders()
	server := &Server{reader: &bytes.Buffer{}, writer: &bytes.Buffer{},
		checkSvc: service.NewCheckService(), topoSvc: &stubTopoSvc{},
		credEnv: omada, opnsenseCredEnv: opnsense}
	text, isErr := server.DispatchToolForTest(context.Background(), "topology", map[string]interface{}{})
	if !isErr || !strings.Contains(text, "at least one provider") {
		t.Errorf("got (%q, %v)", text, isErr)
	}
}

func TestDispatchTopology_ReportError(t *testing.T) {
	hermeticCreds(t)
	omada, opnsense := credEnvReaders()
	server := &Server{reader: &bytes.Buffer{}, writer: &bytes.Buffer{},
		checkSvc: service.NewCheckService(),
		topoSvc:  &stubTopoSvc{err: errors.New("fetch failed")},
		credEnv:  omada, opnsenseCredEnv: opnsense}
	text, isErr := server.DispatchToolForTest(context.Background(), "topology", map[string]interface{}{
		"opnsense_host": "fw.local", "opnsense_api_key": "key1", "opnsense_api_secret": "secret1",
	})
	if !isErr || !strings.Contains(text, "topology report failed") || !strings.Contains(text, "fetch failed") {
		t.Errorf("got (%q, %v)", text, isErr)
	}
}

// fwOnlyOmadaSvc succeeds at ALG and fails at firewall settings so the
// get_nat_settings dispatch test can exercise the second (firewall) error
// branch, which a plain err stub cannot reach.
type fwOnlyOmadaSvc struct {
	stubOmadaSvc
}

func (s *fwOnlyOmadaSvc) GetFirewallSettings(_ context.Context, opts service.OmadaOptions) (*service.OmadaFirewallSettings, error) {
	s.calls++
	s.lastOpts = opts
	return nil, errors.New("firewall endpoint missing")
}

func TestDispatchOmadaNatReads_Errors(t *testing.T) {
	hermeticCreds(t)
	args := map[string]interface{}{"host": "omada.local", "client_id": "cid-1", "client_secret": "pw"}

	cases := []struct {
		tool, want string
	}{
		{"omada_list_port_forwardings", "omada port forwardings request failed"},
		{"omada_list_one_to_one_nat", "omada one-to-one NAT request failed"},
		{"omada_nat_facts", "omada nat facts request failed"},
		{"omada_list_switch_ports", "omada switch ports request failed"},
		{"omada_list_lan_profiles", "omada lan profiles request failed"},
		{"omada_get_uplink_info", "omada uplink info request failed"},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			server := serverWithOmadaStub(&stubOmadaSvc{err: errors.New("controller down")})
			args := map[string]interface{}{"host": "omada.local", "client_id": "cid-1", "client_secret": "pw"}
			if tc.tool == "omada_get_uplink_info" {
				args["device_mac"] = "aa:bb:cc:dd:ee:00"
			}
			text, isErr := server.DispatchToolForTest(context.Background(), tc.tool, args)
			if !isErr || !strings.Contains(text, tc.want) || !strings.Contains(text, "controller down") {
				t.Errorf("got (%q, %v), want %q", text, isErr, tc.want)
			}
		})
	}

	// ALG failure is reported by the first read.
	t.Run("get_nat_settings_alg_error", func(t *testing.T) {
		server := serverWithOmadaStub(&stubOmadaSvc{err: errors.New("alg down")})
		text, isErr := server.DispatchToolForTest(context.Background(), "omada_get_nat_settings", args)
		if !isErr || !strings.Contains(text, "omada ALG settings request failed") {
			t.Errorf("got (%q, %v)", text, isErr)
		}
	})

	// Firewall failure is reported only when ALG succeeds.
	t.Run("get_nat_settings_firewall_error", func(t *testing.T) {
		omadaEnv, opnsenseEnv := credEnvReaders()
		server := &Server{reader: &bytes.Buffer{}, writer: &bytes.Buffer{},
			checkSvc: service.NewCheckService(),
			omadaSvc: &fwOnlyOmadaSvc{stubOmadaSvc{alg: &service.OmadaALGSettings{}}},
			topoSvc:  &stubTopoSvc{},
			credEnv:  omadaEnv, opnsenseCredEnv: opnsenseEnv}
		text, isErr := server.DispatchToolForTest(context.Background(), "omada_get_nat_settings", args)
		if !isErr || !strings.Contains(text, "omada firewall settings request failed") ||
			!strings.Contains(text, "firewall endpoint missing") {
			t.Errorf("got (%q, %v)", text, isErr)
		}
	})
}

func TestDispatchOpnsenseNatReads_Errors(t *testing.T) {
	hermeticCreds(t)
	args := map[string]interface{}{"host": "fw.local", "api_key": "key1", "api_secret": "secret1"}

	cases := []struct {
		tool, want string
	}{
		{"opnsense_list_port_forward_rules", "opnsense port forward rules request failed"},
		{"opnsense_list_one_to_one_rules", "opnsense one-to-one rules request failed"},
		{"opnsense_list_source_nat_rules", "opnsense source NAT rules request failed"},
		{"opnsense_list_aliases", "opnsense aliases request failed"},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			server := serverWithOpnsenseStub(&stubOpnsenseSvc{err: errors.New("controller down")})
			text, isErr := server.DispatchToolForTest(context.Background(), tc.tool, args)
			if !isErr || !strings.Contains(text, tc.want) || !strings.Contains(text, "controller down") {
				t.Errorf("got (%q, %v), want %q", text, isErr, tc.want)
			}
		})
	}
}

// A host present without credentials must fail the topology call with the
// options-builder message, not silently skip the provider (a partial picture
// would mislead the double-NAT verdict).
func TestDispatchTopology_MissingCredentials(t *testing.T) {
	hermeticCreds(t)
	omada, opnsense := credEnvReaders()
	server := &Server{reader: &bytes.Buffer{}, writer: &bytes.Buffer{},
		checkSvc: service.NewCheckService(), topoSvc: &stubTopoSvc{},
		credEnv: omada, opnsenseCredEnv: opnsense}

	text, isErr := server.DispatchToolForTest(context.Background(), "topology", map[string]interface{}{
		"omada_host": "omada.local",
	})
	if !isErr || !strings.Contains(text, "client_id and client_secret parameters are required") {
		t.Errorf("omada: got (%q, %v), want missing-credential message", text, isErr)
	}

	text, isErr = server.DispatchToolForTest(context.Background(), "topology", map[string]interface{}{
		"opnsense_host": "fw.local",
	})
	if !isErr || !strings.Contains(text, "api_key and api_secret parameters are required") {
		t.Errorf("opnsense: got (%q, %v), want missing-credential message", text, isErr)
	}
}

// Every NAT read tool must reject a call that carries no host with the
// options-builder message, before any provider call happens.
func TestDispatchNatReads_MissingHost(t *testing.T) {
	hermeticCreds(t)

	omadaTools := []string{
		"omada_list_port_forwardings",
		"omada_list_one_to_one_nat",
		"omada_get_nat_settings",
		"omada_nat_facts",
		"omada_get_uplink_info",
		"omada_list_switch_ports",
		"omada_list_lan_profiles",
		"omada_list_gateway_dhcp_users",
		"omada_get_client_topology",
		"omada_plan_port",
		"omada_apply_port_profile",
	}
	for _, tool := range omadaTools {
		t.Run(tool, func(t *testing.T) {
			server := serverWithOmadaStub(&stubOmadaSvc{})
			text, isErr := server.DispatchToolForTest(context.Background(), tool, map[string]interface{}{})
			if !isErr || !strings.Contains(text, "host parameter is required") {
				t.Errorf("got (%q, %v), want host-parameter error", text, isErr)
			}
		})
	}

	opnsenseTools := []string{
		"opnsense_list_port_forward_rules",
		"opnsense_list_one_to_one_rules",
		"opnsense_list_source_nat_rules",
		"opnsense_list_aliases",
		"opnsense_get_nat",
		"opnsense_list_services",
		"opnsense_list_gateways",
		"opnsense_inventory",
	}
	for _, tool := range opnsenseTools {
		t.Run(tool, func(t *testing.T) {
			server := serverWithOpnsenseStub(&stubOpnsenseSvc{})
			text, isErr := server.DispatchToolForTest(context.Background(), tool, map[string]interface{}{})
			if !isErr || !strings.Contains(text, "host parameter is required") {
				t.Errorf("got (%q, %v), want host-parameter error", text, isErr)
			}
		})
	}
}
