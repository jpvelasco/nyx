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

	"github.com/jpvelasco/nyx/internal/backends"
	"github.com/jpvelasco/nyx/internal/backends/system"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/service"
)

func newTestServer() *Server {
	return &Server{reader: &bytes.Buffer{}, writer: &bytes.Buffer{}, checkSvc: service.NewCheckService(), omadaSvc: service.NewOmadaService()}
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
	if len(lines) != 4 {
		t.Fatalf("expected 4 responses, got %d: %q", len(lines), out.String())
	}
	for i, wantID := range []string{"1", "2", "3", "4"} {
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
	if !strings.Contains(lines[3], `"subnet parameter is required"`) {
		t.Errorf("expected required-param error for discover_subnet, got %s", lines[3])
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
	if out.Len() != 0 {
		t.Errorf("expected no responses for notifications/malformed input, got %q", out.String())
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
	if len(list.Tools) != 20 {
		t.Fatalf("expected 20 tools, got %d", len(list.Tools))
	}
	names := map[string]string{}
	for _, tl := range list.Tools {
		names[tl.Name] = tl.Description
		if tl.InputSchema.Type != "object" {
			t.Errorf("tool %s: schema type = %q", tl.Name, tl.InputSchema.Type)
		}
	}
	for _, want := range []string{"discover_subnet", "check_routes", "check_vpn", "verify_isolation", "run_audit", "load_spec", "get_interfaces", "ping_target", "run_doctor", "provider_list", "omada_get_info", "omada_list_networks", "omada_list_acls", "omada_list_clients", "omada_import", "omada_plan", "opnsense_get_info", "opnsense_list_interfaces", "opnsense_list_firewall_rules", "opnsense_list_clients"} {
		if _, ok := names[want]; !ok {
			t.Errorf("missing tool %q", want)
		}
	}
	dc := list.Tools[0]
	if len(dc.InputSchema.Required) != 1 || dc.InputSchema.Required[0] != "subnet" {
		t.Errorf("discover_subnet required = %v", dc.InputSchema.Required)
	}
}

func TestHandleToolCall_NotInitialized(t *testing.T) {
	resp := newTestServer().handleToolCall(context.Background(), &jsonRPCRequest{ID: json.RawMessage(`1`)})
	if resp.Error == nil || resp.Error.Code != -32002 {
		t.Fatalf("expected -32002, got %+v", resp.Error)
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
	if _, err := sp.WriteString("version: 1\nsite: test\n"); err != nil {
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
	if !strings.Contains(text, "spec_file") || !strings.Contains(text, "nmap_installed") {
		t.Errorf("expected nmap + spec checks, got: %s", text)
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
	if stub.lastOpts.Password != "" {
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
	text, isErr := newTestServer().DispatchToolForTest(context.Background(), "omada_list_networks", map[string]interface{}{
		"host": "omada.local",
	})
	if !isErr || !strings.Contains(text, "username and password parameters are required") {
		t.Errorf("got (%q, %v)", text, isErr)
	}
}

func TestDispatchOmadaListNetworks_Success(t *testing.T) {
	stub := &stubOmadaSvc{networks: []service.OmadaNetwork{
		{ID: "n1", Name: "Trusted", VLANID: 10, CIDR: "10.0.10.0/24", Gateway: "10.0.10.1", DHCPEnabled: true},
	}}
	server := serverWithOmadaStub(stub)
	text, isErr := server.DispatchToolForTest(context.Background(), "omada_list_networks", map[string]interface{}{
		"host":     "omada.local",
		"username": "admin",
		"password": "pw",
		"site":     "HQ",
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
	if stub.lastOpts.Host != "omada.local" || stub.lastOpts.Username != "admin" || stub.lastOpts.Password != "pw" || stub.lastOpts.Site != "HQ" {
		t.Errorf("options = %+v", stub.lastOpts)
	}
	if strings.Contains(text, "pw") {
		t.Error("tool output must not echo the password")
	}
}

func TestDispatchOmadaListNetworks_ServiceError(t *testing.T) {
	stub := &stubOmadaSvc{err: errors.New("site not found")}
	text, isErr := serverWithOmadaStub(stub).DispatchToolForTest(context.Background(), "omada_list_networks", map[string]interface{}{
		"host":     "omada.local",
		"username": "admin",
		"password": "pw",
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
		"host":     "omada.local",
		"username": "admin",
		"password": "pw",
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
		"host":     "omada.local",
		"username": "admin",
		"password": "pw",
	})
	if !isErr || !strings.Contains(text, "omada acls request failed") {
		t.Errorf("got (%q, %v)", text, isErr)
	}
}

func TestDispatchOmadaListClients_Success(t *testing.T) {
	stub := &stubOmadaSvc{clients: []service.OmadaClient{
		{MAC: "aa:bb:cc:dd:ee:ff", IP: "10.0.10.5", Name: "nas", NetworkName: "Trusted", Active: true},
	}}
	text, isErr := serverWithOmadaStub(stub).DispatchToolForTest(context.Background(), "omada_list_clients", map[string]interface{}{
		"host":     "omada.local",
		"username": "admin",
		"password": "pw",
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
		"host":     "omada.local",
		"username": "admin",
		"password": "pw",
	})
	if !isErr || !strings.Contains(text, "omada clients request failed") {
		t.Errorf("got (%q, %v)", text, isErr)
	}
}

func TestDispatchOmadaImport_MissingParams(t *testing.T) {
	server := newTestServer()
	if text, isErr := server.DispatchToolForTest(context.Background(), "omada_import", map[string]interface{}{}); !isErr || !strings.Contains(text, "host parameter is required") {
		t.Errorf("missing host: (%q, %v)", text, isErr)
	}
	if text, isErr := server.DispatchToolForTest(context.Background(), "omada_import", map[string]interface{}{"host": "omada.local"}); !isErr || !strings.Contains(text, "username and password parameters are required") {
		t.Errorf("missing creds: (%q, %v)", text, isErr)
	}
}

func TestDispatchOmadaImport_Success(t *testing.T) {
	stub := &stubOmadaSvc{imp: &service.OmadaImport{
		Site: "HQ", ControllerVersion: "6.4.5.1", NetworkCount: 2, ACLRuleCount: 1, ClientCount: 1,
		Warnings: []string{"note"},
	}}
	text, isErr := serverWithOmadaStub(stub).DispatchToolForTest(context.Background(), "omada_import", map[string]interface{}{
		"host":     "omada.local",
		"username": "admin",
		"password": "pw",
		"site":     "HQ",
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
		t.Error("tool output must not echo the password")
	}
}

func TestDispatchOmadaImport_ServiceError(t *testing.T) {
	stub := &stubOmadaSvc{err: errors.New("import failed")}
	text, isErr := serverWithOmadaStub(stub).DispatchToolForTest(context.Background(), "omada_import", map[string]interface{}{
		"host":     "omada.local",
		"username": "admin",
		"password": "pw",
	})
	if !isErr || !strings.Contains(text, "omada import request failed") {
		t.Errorf("got (%q, %v)", text, isErr)
	}
}

func TestDispatchOmadaPlan_MissingParams(t *testing.T) {
	server := newTestServer()
	if text, isErr := server.DispatchToolForTest(context.Background(), "omada_plan", map[string]interface{}{}); !isErr || !strings.Contains(text, "host parameter is required") {
		t.Errorf("missing host: (%q, %v)", text, isErr)
	}
	if text, isErr := server.DispatchToolForTest(context.Background(), "omada_plan", map[string]interface{}{"host": "omada.local"}); !isErr || !strings.Contains(text, "username and password parameters are required") {
		t.Errorf("missing creds: (%q, %v)", text, isErr)
	}
	if text, isErr := server.DispatchToolForTest(context.Background(), "omada_plan", map[string]interface{}{
		"host": "omada.local", "username": "admin", "password": "pw",
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
		"host":     "omada.local",
		"username": "admin",
		"password": "pw",
		"site":     "HQ",
		"spec":     "version: 1\nsite: HQ\npolicies: []\n",
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
		t.Error("tool output must not echo the password")
	}
}

func TestDispatchOmadaPlan_ServiceError(t *testing.T) {
	stub := &stubOmadaSvc{err: errors.New("plan failed")}
	text, isErr := serverWithOmadaStub(stub).DispatchToolForTest(context.Background(), "omada_plan", map[string]interface{}{
		"host":     "omada.local",
		"username": "admin",
		"password": "pw",
		"spec":     "version: 1\nsite: HQ\npolicies: []\n",
	})
	if !isErr || !strings.Contains(text, "omada plan request failed") {
		t.Errorf("got (%q, %v)", text, isErr)
	}
	if strings.Contains(text, "pw") {
		t.Error("error output must not echo the password")
	}
}

func TestDispatchOpnsense_MissingParams(t *testing.T) {
	server := newTestServer()
	for _, tool := range []string{"opnsense_get_info", "opnsense_list_interfaces", "opnsense_list_firewall_rules", "opnsense_list_clients"} {
		if text, isErr := server.DispatchToolForTest(context.Background(), tool, map[string]interface{}{}); !isErr || !strings.Contains(text, "host parameter is required") {
			t.Errorf("%s missing host: (%q, %v)", tool, text, isErr)
		}
		if text, isErr := server.DispatchToolForTest(context.Background(), tool, map[string]interface{}{"host": "fw.local"}); !isErr || !strings.Contains(text, "api key and api secret parameters are required") {
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

// stubOmadaSvc is a hermetic stand-in for the Omada observation surface.
type stubOmadaSvc struct {
	info     *service.OmadaInfo
	networks []service.OmadaNetwork
	acls     []service.OmadaACLRule
	clients  []service.OmadaClient
	imp      *service.OmadaImport
	plan     *service.OmadaPlan
	err      error
	lastOpts service.OmadaOptions
	calls    int
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

// stubOpnsenseSvc is a hermetic stand-in for the OPNsense observation surface.
type stubOpnsenseSvc struct {
	info       *service.OpnsenseInfo
	interfaces []service.OpnsenseInterface
	rules      []service.OpnsenseFirewallRule
	clients    []service.OpnsenseClient
	err        error
	lastOpts   service.OpnsenseOptions
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

func serverWithOpnsenseStub(stub *stubOpnsenseSvc) *Server {
	return &Server{reader: &bytes.Buffer{}, writer: &bytes.Buffer{}, checkSvc: service.NewCheckService(), opnsenseSvc: stub}
}

func serverWithOmadaStub(stub *stubOmadaSvc) *Server {
	return &Server{reader: &bytes.Buffer{}, writer: &bytes.Buffer{}, checkSvc: service.NewCheckService(), omadaSvc: stub}
}
