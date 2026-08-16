package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jpvelasco/nyx/internal/backends/nmap"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/snapshot"
)

func saveRestoreGlobals(t *testing.T) {
	t.Helper()
	saved := struct {
		jsonOutput        bool
		outputPath        string
		specFile          string
		verbose           bool
		timeout           string
		interfaceOpt      string
		routeTarget       string
		vpnTarget         string
		vpnExpect         string
		isolationFrom     string
		isolationTo       string
		discoverSubnet    string
		discoverTiming    int
		discoverMinRate   int
		providerHost      string
		providerUsername  string
		providerPassword  string
		providerSite      string
		providerDebug     bool
		providerOutFile   string
		providerSkipTLS   bool
		providerCACertPth string
		initOutput        string
		warnVirtual       bool
		skipHostKeyVerify bool
		lastAuditReport   *models.AuditReport
		mcpTransport      string
	}{
		jsonOutput: jsonOutput, outputPath: outputPath, specFile: specFile,
		verbose: verbose, timeout: timeout, interfaceOpt: interfaceOpt,
		routeTarget: routeTarget, vpnTarget: vpnTarget, vpnExpect: vpnExpect,
		isolationFrom: isolationFrom, isolationTo: isolationTo,
		discoverSubnet: discoverSubnet, discoverTiming: discoverTiming, discoverMinRate: discoverMinRate,
		providerHost: providerHost, providerUsername: providerUsername, providerPassword: providerPassword,
		providerSite: providerSite, providerDebug: providerDebug, providerOutFile: providerOutFile,
		providerSkipTLS: providerSkipTLS, providerCACertPth: providerCACertPath,
		initOutput: initOutput, warnVirtual: warnVirtual,
		skipHostKeyVerify: skipHostKeyVerify, lastAuditReport: lastAuditReport,
		mcpTransport: mcpTransport,
	}
	t.Cleanup(func() {
		jsonOutput, outputPath, specFile = saved.jsonOutput, saved.outputPath, saved.specFile
		verbose, timeout, interfaceOpt = saved.verbose, saved.timeout, saved.interfaceOpt
		routeTarget, vpnTarget, vpnExpect = saved.routeTarget, saved.vpnTarget, saved.vpnExpect
		isolationFrom, isolationTo = saved.isolationFrom, saved.isolationTo
		discoverSubnet, discoverTiming, discoverMinRate = saved.discoverSubnet, saved.discoverTiming, saved.discoverMinRate
		providerHost, providerUsername, providerPassword = saved.providerHost, saved.providerUsername, saved.providerPassword
		providerSite, providerDebug, providerOutFile = saved.providerSite, saved.providerDebug, saved.providerOutFile
		providerSkipTLS, providerCACertPath = saved.providerSkipTLS, saved.providerCACertPth
		initOutput, warnVirtual = saved.initOutput, saved.warnVirtual
		skipHostKeyVerify, lastAuditReport = saved.skipHostKeyVerify, saved.lastAuditReport
		mcpTransport = saved.mcpTransport
	})
}

func writeSpec(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "spec.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// ---------------------------------------------------------------------------
// doctor helpers
// ---------------------------------------------------------------------------

func TestDoctorTag(t *testing.T) {
	cases := []struct {
		status models.Status
		want   string
	}{
		{models.StatusPass, "[ OK ]"},
		{models.StatusFail, "[FAIL]"},
		{models.StatusWarn, "[WARN]"},
		{models.StatusError, "[ERR ]"},
		{models.StatusSkip, "[ERR ]"},
		{"unknown", "[ERR ]"},
	}
	for _, tc := range cases {
		if got := doctorTag(tc.status); got != tc.want {
			t.Errorf("doctorTag(%q) = %q, want %q", tc.status, got, tc.want)
		}
	}
}

func TestRunSpecChecks_ValidSpec(t *testing.T) {
	path := writeSpec(t, "version: 1\nsite: test\n")
	checks := runSpecChecks(path)
	if len(checks) != 3 {
		t.Fatalf("expected 3 checks, got %d", len(checks))
	}
	for _, c := range checks {
		if c.Status != models.StatusPass {
			t.Errorf("%s: status = %s, want pass (%s)", c.CheckType, c.Status, c.Summary)
		}
	}
}

func TestRunSpecChecks_MissingFile(t *testing.T) {
	checks := runSpecChecks(filepath.Join(t.TempDir(), "missing.yaml"))
	if len(checks) != 1 {
		t.Fatalf("expected 1 check, got %d", len(checks))
	}
	if checks[0].Status != models.StatusFail || checks[0].CheckType != "spec_file" {
		t.Errorf("unexpected check: %+v", checks[0])
	}
}

func TestRunSpecChecks_InvalidYAML(t *testing.T) {
	path := writeSpec(t, "version: [not")
	checks := runSpecChecks(path)
	if len(checks) != 2 {
		t.Fatalf("expected 2 checks, got %d", len(checks))
	}
	if checks[0].Status != models.StatusPass {
		t.Errorf("file check should pass, got %s", checks[0].Status)
	}
	if checks[1].Status != models.StatusFail || checks[1].CheckType != "spec_valid" {
		t.Errorf("unexpected check: %+v", checks[1])
	}
}

func TestRunSpecChecks_InvalidSpecVersion(t *testing.T) {
	path := writeSpec(t, "version: 99\nsite: test\n")
	checks := runSpecChecks(path)
	if len(checks) != 2 {
		t.Fatalf("expected 2 checks, got %d", len(checks))
	}
	if checks[1].Status != models.StatusFail {
		t.Errorf("expected validation failure, got %s", checks[1].Status)
	}
}

func TestRunSpecChecks_UnresolvedReferences(t *testing.T) {
	path := writeSpec(t, `version: 1
site: test
networks:
  - name: lan
    cidr: 192.168.1.0/24
vpn:
  - name: vpn0
    type: wireguard
    expected_routes: [10.0.0.0/8]
assertions:
  - type: subnet_discovery
    network: missing-net
  - type: vpn_route
    vpn: missing-vpn
    target: 10.0.0.1
`)
	checks := runSpecChecks(path)
	if len(checks) != 3 {
		t.Fatalf("expected 3 checks, got %d", len(checks))
	}
	ref := checks[2]
	if ref.Status != models.StatusFail || ref.CheckType != "spec_references" {
		t.Fatalf("expected reference failures, got %+v", ref)
	}
	if len(ref.Violations) != 2 {
		t.Errorf("expected 2 violations, got %v", ref.Violations)
	}
}

func TestRunSpecChecks_ProbeReachability(t *testing.T) {
	path := writeSpec(t, `version: 1
site: test
probes:
  - name: p1
    host: 127.0.0.1
    user: test
`)
	checks := runSpecChecks(path)
	if len(checks) != 4 {
		t.Fatalf("expected 4 checks, got %d", len(checks))
	}
	probe := checks[3]
	if probe.CheckType != "probe_reachable" {
		t.Fatalf("expected probe check, got %+v", probe)
	}
	// 127.0.0.1:22 is either refused (fail) or a local sshd (pass); both are fine.
	if probe.Status != models.StatusPass && probe.Status != models.StatusFail {
		t.Errorf("unexpected probe status: %s", probe.Status)
	}
}

// ---------------------------------------------------------------------------
// interfaces helpers
// ---------------------------------------------------------------------------

func TestParseIPNet(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"192.168.1.5/24", "192.168.1.5/24", true},
		{"10.0.0.7", "10.0.0.7/32", true},
		{"not-an-ip", "", false},
		{"", "", false},
	}
	for _, tc := range cases {
		ipnet, ok := parseIPNet(tc.in)
		if ok != tc.ok {
			t.Errorf("parseIPNet(%q) ok = %v, want %v", tc.in, ok, tc.ok)
			continue
		}
		if ok && ipnet.String() != tc.want {
			t.Errorf("parseIPNet(%q) = %s, want %s", tc.in, ipnet, tc.want)
		}
	}
}

func TestParseAsIPNet_Invalid(t *testing.T) {
	if ipnet, ok := parseAsIPNet("bad"); ok || ipnet != nil {
		t.Errorf("expected failure, got %v, %v", ipnet, ok)
	}
}

// ---------------------------------------------------------------------------
// init helpers
// ---------------------------------------------------------------------------

func TestIsVirtualIface(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"vmnet8", true},
		{"vboxnet0", true},
		{"veth0", true},
		{"docker0", true},
		{"br-1234", true},
		{"virbr0", true},
		{"VMware Network Adapter VMnet1", true},
		{"VirtualBox Host-Only Network", true},
		{"vEthernet (WSL)", true},
		{"TAP-Windows Adapter V9", false},
		{"OpenVPN TAP Adapter", true},
		{"Ethernet", false},
		{"Wi-Fi", false},
		{"en0", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isVirtualIface(tc.name); got != tc.want {
			t.Errorf("isVirtualIface(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestIsInvalidGW(t *testing.T) {
	cases := []struct {
		gw   string
		want bool
	}{
		{"", true},
		{"0.0.0.0", true},
		{"On-link", true},
		{"not-an-ip", true},
		{"192.168.1.1", false},
		{"fe80::1", false},
	}
	for _, tc := range cases {
		if got := isInvalidGW(tc.gw); got != tc.want {
			t.Errorf("isInvalidGW(%q) = %v, want %v", tc.gw, got, tc.want)
		}
	}
}

func TestIsRFC1918(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true},
		{"192.168.1.100", true},
		{"192.168.255.254", true},
		{"8.8.8.8", false},
		{"172.32.0.1", false},
		{"169.254.1.1", false},
	}
	for _, tc := range cases {
		if got := isRFC1918(net.ParseIP(tc.ip)); got != tc.want {
			t.Errorf("isRFC1918(%q) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestGuessGateway(t *testing.T) {
	cases := []struct {
		ip   string
		want string
	}{
		{"192.168.1.0", "192.168.1.1"},
		{"10.0.0.0", "10.0.0.1"},
		{"172.16.5.0", "172.16.5.1"},
	}
	for _, tc := range cases {
		if got := guessGateway(net.ParseIP(tc.ip)); got != tc.want {
			t.Errorf("guessGateway(%q) = %q, want %q", tc.ip, got, tc.want)
		}
	}
}

func TestInferNetworkName(t *testing.T) {
	cases := []struct {
		cidr  string
		hosts int
		want  string
	}{
		{"10.0.0.0/8", 5, "infrastructure"},
		{"10.0.0.0/16", 60, "infrastructure"},
		{"172.16.0.0/23", 60, "servers"},
		{"192.168.1.0/28", 2, "iot"},
		{"192.168.2.0/28", 10, "iot"},
		{"192.168.3.0/24", 3, "guest"},
		{"192.168.4.0/24", 30, "lan"},
		{"192.168.5.0/24", 15, "clients"},
		{"192.168.6.0/24", 4, "guest"},
		{"192.168.6.0/24", 8, "segment"},
		{"invalid", 0, "net"},
	}
	for _, tc := range cases {
		if got := inferNetworkName(tc.cidr, tc.hosts); got != tc.want {
			t.Errorf("inferNetworkName(%q, %d) = %q, want %q", tc.cidr, tc.hosts, got, tc.want)
		}
	}
}

func TestNameForCIDR_Collision(t *testing.T) {
	used := map[string]bool{}
	if got := nameForCIDR("192.168.1.0/24", "", 30, used); got != "lan" {
		t.Errorf("first = %q, want lan", got)
	}
	if got := nameForCIDR("192.168.2.0/24", "", 30, used); got != "lan2" {
		t.Errorf("second = %q, want lan2", got)
	}
	if got := nameForCIDR("192.168.3.0/24", "", 30, used); got != "lan3" {
		t.Errorf("third = %q, want lan3", got)
	}
}

func TestBuildInitSpec(t *testing.T) {
	spec := buildInitSpec([]initNet{
		{cidr: "192.168.1.0/24", gateway: "192.168.1.1", localIP: "192.168.1.10", hosts: 25, ifaceName: "Ethernet"},
		{cidr: "10.0.0.0/28", gateway: "10.0.0.1", localIP: "10.0.0.5", hosts: 3, ifaceName: "vEthernet (WSL)"},
	})
	if spec.Version != 1 {
		t.Errorf("version = %d", spec.Version)
	}
	if spec.Site != "site-192-168" {
		t.Errorf("site = %q", spec.Site)
	}
	if len(spec.Networks) != 2 {
		t.Fatalf("expected 2 networks, got %d", len(spec.Networks))
	}
	lan := spec.Networks[0]
	if lan.Name != "lan" || lan.Zone != "clients" || lan.Gateway != "192.168.1.1" {
		t.Errorf("unexpected lan network: %+v", lan)
	}
	iot := spec.Networks[1]
	if iot.Name != "iot" || iot.Zone != "iot" {
		t.Errorf("unexpected iot network: %+v", iot)
	}
	// lan: discovery + health + dns (real iface). iot: discovery + health (virtual iface, no dns).
	if len(spec.Assertions) != 5 {
		t.Fatalf("expected 5 assertions, got %d", len(spec.Assertions))
	}
	if spec.Assertions[0].ExpectHostsMin == nil || spec.Assertions[1].ExpectHostsMin != nil {
		t.Errorf("host-min only on non-empty network: %+v %+v", spec.Assertions[0], spec.Assertions[1])
	}
	// iot should not get a dns_check.
	for _, a := range spec.Assertions {
		if a.Type == "dns_check" {
			if a.Server == "10.0.0.1" {
				t.Error("virtual iface must not get dns_check against its gateway")
			}
		}
	}
	// iot must be isolated from clients.
	if len(spec.Policies) != 1 || spec.Policies[0].(map[string]interface{})["name"] != "isolate-iot-from-clients" {
		t.Errorf("expected isolation policy, got %v", spec.Policies)
	}
	// probe for iot (not runner network), none for lan (runner).
	if len(spec.Probes) != 1 {
		t.Errorf("expected 1 probe, got %d", len(spec.Probes))
	}
}

func TestDetectLocalCIDRs(t *testing.T) {
	saveRestoreGlobals(t)
	cidrs, err := detectLocalCIDRs("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Results depend on the machine; just verify shape (no gateways of 0.0.0.0).
	for _, c := range cidrs {
		if isInvalidGW(c.gateway) {
			t.Errorf("detectLocalCIDRs returned invalid gateway %q for %s", c.gateway, c.cidr)
		}
	}
}

func TestDetectLocalCIDRs_NarrowFilter(t *testing.T) {
	cidrs, err := detectLocalCIDRs("definitely-not-a-real-interface-xyz")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cidrs) != 0 {
		t.Errorf("expected no CIDRs for unknown interface, got %d", len(cidrs))
	}
}

// ---------------------------------------------------------------------------
// environment briefing
// ---------------------------------------------------------------------------

func TestGetEnvironmentBriefing_NoSpec(t *testing.T) {
	brief := GetEnvironmentBriefing(nil)
	if brief.Summary == "" {
		t.Error("summary should not be empty")
	}
	if brief.InterfaceCount != len(brief.ActiveInterfaces) {
		t.Errorf("count mismatch: %d vs %d", brief.InterfaceCount, len(brief.ActiveInterfaces))
	}
}

func TestGetEnvironmentBriefing_WithSpec(t *testing.T) {
	spec := &intent.Spec{
		Version: 1,
		Site:    "test",
		Networks: []intent.Network{
			{Name: "lan", CIDR: "0.0.0.0/0"},
		},
	}
	brief := GetEnvironmentBriefing(spec)
	if brief.Summary == "" {
		t.Error("summary should not be empty")
	}
}

func TestRenderEnvironmentBriefing(t *testing.T) {
	brief := EnvironmentBriefing{
		Summary:          "You're on a single interface: eth0",
		CurrentIPs:       []string{"192.168.1.5"},
		ActiveInterfaces: []string{"eth0"},
		MatchedNetworks:  []string{"lan"},
		Recommendations:  []string{"use --interface"},
	}
	out := RenderEnvironmentBriefing(brief)
	for _, want := range []string{"Where We Are", "eth0", "lan", "--interface"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestRenderEnvironmentBriefing_Empty(t *testing.T) {
	out := RenderEnvironmentBriefing(EnvironmentBriefing{Summary: "nothing"})
	if !strings.Contains(out, "nothing") {
		t.Errorf("output = %q", out)
	}
}

func TestMapIfaceToIP(t *testing.T) {
	m := mapIfaceToIP([]string{"__definitely_missing_iface__"}, nil)
	if len(m) != 0 {
		t.Errorf("expected empty map for missing iface, got %v", m)
	}
}

func TestExecute(t *testing.T) {
	registerFakeProvider(t)
	saveRestoreGlobals(t)
	rootCmd.SetArgs([]string{"version"})
	t.Cleanup(func() { rootCmd.SetArgs(nil) })
	out := captureStdout(func() {
		if err := Execute(); err != nil {
			t.Fatalf("Execute: %v", err)
		}
	})
	if !strings.Contains(out, "nyx v") {
		t.Errorf("expected version output, got %q", out)
	}
}

func TestGetWriter_Error(t *testing.T) {
	saveRestoreGlobals(t)
	outputPath = t.TempDir() // a directory, not a file
	if _, err := getWriter(); err == nil {
		t.Fatal("expected error opening a directory as an output file")
	}
}

// ---------------------------------------------------------------------------
// drift rendering
// ---------------------------------------------------------------------------

func TestStatusTag(t *testing.T) {
	cases := []struct {
		status models.Status
		want   string
	}{
		{models.StatusPass, "[PASS]"},
		{models.StatusFail, "[FAIL]"},
		{models.StatusWarn, "[WARN]"},
		{models.StatusError, "[ERR ]"},
		{models.StatusSkip, "[SKIP]"},
		{"weird", "[????]"},
	}
	for _, tc := range cases {
		if got := statusTag(tc.status); got != tc.want {
			t.Errorf("statusTag(%q) = %q, want %q", tc.status, got, tc.want)
		}
	}
}

func TestRenderDrift_AllSections(t *testing.T) {
	finding := models.CheckResult{CheckType: "route_check", Status: models.StatusFail, Summary: "broke"}
	drift := &snapshot.DriftResult{
		BaselineTime:   time.Unix(0, 0),
		CurrentTime:    time.Unix(1, 0),
		BaselineStatus: models.StatusPass,
		CurrentStatus:  models.StatusFail,
		NewFailures:    []models.CheckResult{finding},
		Degraded:       []models.CheckResult{finding},
		FixedFailures:  []models.CheckResult{finding},
		Improved:       []models.CheckResult{finding},
		NewWarnings:    []models.CheckResult{finding},
		Summary: snapshot.DriftSummary{
			BaselinePass: 5, BaselineFail: 0, BaselineWarn: 1, BaselineError: 0,
			CurrentPass: 3, CurrentFail: 2, CurrentWarn: 0, CurrentError: 0,
			NetChange: "+2 failures",
		},
	}
	// renderDrift prints to stdout; capture it.
	out := captureStdout(func() { renderDrift(drift) })
	for _, want := range []string{"Drift Report", "New failures", "Degraded", "Fixed", "Improved", "New warnings", "+2 failures"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestRenderDrift_NoDrift(t *testing.T) {
	drift := &snapshot.DriftResult{
		BaselineTime:   time.Unix(0, 0),
		CurrentTime:    time.Unix(1, 0),
		BaselineStatus: models.StatusPass,
		CurrentStatus:  models.StatusPass,
	}
	out := captureStdout(func() { renderDrift(drift) })
	if !strings.Contains(out, "All good") {
		t.Errorf("expected no-drift message, got: %s", out)
	}
}

// ---------------------------------------------------------------------------
// provider helpers
// ---------------------------------------------------------------------------

func TestMarshalSpecYAML(t *testing.T) {
	spec := &intent.Spec{Version: 1, Site: "test", Networks: []intent.Network{{Name: "lan", CIDR: "192.168.1.0/24"}}}
	out, err := marshalSpecYAML(&providers.ImportResult{
		Spec:         spec,
		ProviderInfo: providers.ProviderInfo{Host: "10.0.0.1", Version: "1.2.3"},
	}, "omada")
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if !strings.Contains(text, "# Generated by nyx omada import") {
		t.Errorf("missing header: %s", text)
	}
	if !strings.Contains(text, "192.168.1.0/24") {
		t.Errorf("missing network: %s", text)
	}
}

// ---------------------------------------------------------------------------
// fake provider for provider command tests
// ---------------------------------------------------------------------------

type fakeProvider struct {
	name string
}

func (f *fakeProvider) Name() string { return f.name }
func (f *fakeProvider) Capabilities() []string {
	return []string{"info", "import", "check"}
}
func (f *fakeProvider) Info(ctx context.Context, opts providers.ImportOptions) (*providers.ProviderInfo, error) {
	return &providers.ProviderInfo{Provider: f.name, Host: opts.Host, Version: "9.9.9", Extra: map[string]string{"site": "s1"}}, nil
}
func (f *fakeProvider) ImportSpec(ctx context.Context, opts providers.ImportOptions) (*providers.ImportResult, error) {
	return &providers.ImportResult{
		Spec:         &intent.Spec{Version: 1, Site: "imported"},
		ProviderInfo: providers.ProviderInfo{Host: opts.Host, Version: "9.9.9"},
		NetworkCount: 2,
		PolicyCount:  1,
		ClientCount:  4,
		Warnings:     []string{"some warning"},
	}, nil
}
func (f *fakeProvider) Check(ctx context.Context, opts providers.ImportOptions) (*providers.AuditResult, error) {
	return &providers.AuditResult{Report: &models.AuditReport{Audit: "check", Status: models.StatusPass}}, nil
}
func (f *fakeProvider) CheckACL(ctx context.Context, req providers.ACLCheckRequest, opts providers.ImportOptions) (*models.CheckResult, error) {
	return models.NewCheckResult("fake", "acl_check", "local", req.PolicyName), nil
}

func (e *errProvider) Check(ctx context.Context, opts providers.ImportOptions) (*providers.AuditResult, error) {
	return nil, fmt.Errorf("connection refused")
}

func registerFakeProvider(t *testing.T) {
	t.Helper()
	providers.Reset()
	t.Cleanup(providers.Reset)
	if err := providers.Register(&fakeProvider{name: "fake"}); err != nil {
		t.Fatal(err)
	}
}

func TestBuildInfoCmd_Run(t *testing.T) {
	registerFakeProvider(t)
	saveRestoreGlobals(t)
	cmd := buildInfoCmd(&fakeProvider{name: "fake"})
	providerHost = "10.0.0.5"
	providerUsername = "admin"
	providerPassword = "pw"
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildInfoCmd_RunJSON(t *testing.T) {
	registerFakeProvider(t)
	saveRestoreGlobals(t)
	jsonOutput = true
	cmd := buildInfoCmd(&fakeProvider{name: "fake"})
	providerHost = "10.0.0.5"
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildInfoCmd_HostFromEnv(t *testing.T) {
	registerFakeProvider(t)
	saveRestoreGlobals(t)
	t.Setenv("OMADA_HOST", "10.0.0.9")
	t.Setenv("OMADA_USERNAME", "env-user")
	t.Setenv("OMADA_PASSWORD", "env-pass")
	cmd := buildInfoCmd(&fakeProvider{name: "fake"})
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("info with OMADA_HOST: %v", err)
	}
}

func TestBuildInfoCmd_MissingHostError(t *testing.T) {
	saveRestoreGlobals(t)
	t.Setenv("OMADA_HOST", "")
	t.Setenv("NYX_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "credentials.json"))
	cmd := buildInfoCmd(&fakeProvider{name: "fake"})
	err := cmd.RunE(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "OMADA_HOST") {
		t.Fatalf("error = %v, want missing-host message naming OMADA_HOST", err)
	}
}

func TestBuildInfoCmd_ProviderError(t *testing.T) {
	saveRestoreGlobals(t)
	errCmd := buildInfoCmd(&errProvider{})
	if err := errCmd.RunE(errCmd, nil); err == nil {
		t.Fatal("expected error from provider")
	}
}

type errProvider struct{ fakeProvider }

func (e *errProvider) Info(ctx context.Context, opts providers.ImportOptions) (*providers.ProviderInfo, error) {
	return nil, fmt.Errorf("connection refused")
}

func (e *errProvider) ImportSpec(ctx context.Context, opts providers.ImportOptions) (*providers.ImportResult, error) {
	return nil, fmt.Errorf("connection refused")
}

func TestBuildImportCmd_RunStdout(t *testing.T) {
	registerFakeProvider(t)
	saveRestoreGlobals(t)
	cmd := buildImportCmd(&fakeProvider{name: "fake"})
	providerHost = "10.0.0.5"
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildImportCmd_RunToFile(t *testing.T) {
	registerFakeProvider(t)
	saveRestoreGlobals(t)
	cmd := buildImportCmd(&fakeProvider{name: "fake"})
	providerHost = "10.0.0.5"
	providerOutFile = filepath.Join(t.TempDir(), "spec.yaml")
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := os.Stat(providerOutFile); err != nil {
		t.Errorf("expected spec file written: %v", err)
	}
}

func TestBuildImportCmd_WriteError(t *testing.T) {
	registerFakeProvider(t)
	saveRestoreGlobals(t)
	cmd := buildImportCmd(&fakeProvider{name: "fake"})
	providerHost = "10.0.0.5"
	providerOutFile = filepath.Join(t.TempDir(), "no", "such", "dir", "spec.yaml")
	if err := cmd.RunE(cmd, nil); err == nil {
		t.Fatal("expected write error")
	}
}

func TestBuildImportCmd_InvalidTimeout(t *testing.T) {
	registerFakeProvider(t)
	saveRestoreGlobals(t)
	cmd := buildImportCmd(&fakeProvider{name: "fake"})
	providerHost = "10.0.0.5"
	timeout = "not-a-duration" // must error, not fall back (#132)
	if err := cmd.RunE(cmd, nil); err == nil {
		t.Fatal("expected invalid --timeout error")
	} else if !strings.Contains(err.Error(), "invalid --timeout") {
		t.Errorf("expected invalid --timeout error, got: %v", err)
	}
}

func TestBuildImportCmd_ProviderError(t *testing.T) {
	saveRestoreGlobals(t)
	cmd := buildImportCmd(&errProvider{})
	if err := cmd.RunE(cmd, nil); err == nil {
		t.Fatal("expected error from provider")
	}
}

func TestBuildCheckCmd_Run(t *testing.T) {
	registerFakeProvider(t)
	saveRestoreGlobals(t)
	cmd := buildCheckCmd(&fakeProvider{name: "fake"})
	providerHost = "10.0.0.5"
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildCheckCmd_RunJSON(t *testing.T) {
	registerFakeProvider(t)
	saveRestoreGlobals(t)
	jsonOutput = true
	cmd := buildCheckCmd(&fakeProvider{name: "fake"})
	providerHost = "10.0.0.5"
	if err := cmd.RunE(cmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildCheckCmd_ProviderError(t *testing.T) {
	saveRestoreGlobals(t)
	cmd := buildCheckCmd(&errProvider{})
	if err := cmd.RunE(cmd, nil); err == nil {
		t.Fatal("expected error from provider")
	}
}

func TestProviderListCmd_Human(t *testing.T) {
	registerFakeProvider(t)
	saveRestoreGlobals(t)
	jsonOutput = false
	outputPath = ""
	if err := providerListCmd.RunE(providerListCmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProviderListCmd_JSON(t *testing.T) {
	registerFakeProvider(t)
	saveRestoreGlobals(t)
	jsonOutput = true
	if err := providerListCmd.RunE(providerListCmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// single-check commands (local route table / loopback only)
// ---------------------------------------------------------------------------

func TestCheckRoutesCmd_MissingTarget(t *testing.T) {
	saveRestoreGlobals(t)
	routeTarget = ""
	if err := checkRoutesCmd.RunE(checkRoutesCmd, nil); err == nil {
		t.Fatal("expected --target required error")
	}
}

func TestCheckRoutesCmd_LocalTarget(t *testing.T) {
	saveRestoreGlobals(t)
	routeTarget = "127.0.0.1"
	timeout = "10s"
	if err := checkRoutesCmd.RunE(checkRoutesCmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckRoutesCmd_JSONVerbose(t *testing.T) {
	saveRestoreGlobals(t)
	routeTarget = "127.0.0.1"
	timeout = "10s"
	jsonOutput = true
	verbose = true
	outputPath = filepath.Join(t.TempDir(), "out.json")
	if err := checkRoutesCmd.RunE(checkRoutesCmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckVPNCmd_MissingTarget(t *testing.T) {
	saveRestoreGlobals(t)
	vpnTarget = ""
	if err := checkVPNCmd.RunE(checkVPNCmd, nil); err == nil {
		t.Fatal("expected --target required error")
	}
}

func TestCheckVPNCmd_LocalTarget(t *testing.T) {
	saveRestoreGlobals(t)
	vpnTarget = "127.0.0.1"
	timeout = "10s"
	err := checkVPNCmd.RunE(checkVPNCmd, nil)
	requireExitCode(t, err, 3) // loopback is not a tunnel interface => warn
}

func TestCheckVPNCmd_ExpectOverride(t *testing.T) {
	saveRestoreGlobals(t)
	vpnTarget = "127.0.0.1"
	vpnExpect = "full-tunnel"
	timeout = "10s"
	err := checkVPNCmd.RunE(checkVPNCmd, nil)
	requireExitCode(t, err, 1) // full-tunnel expected, loopback not via tunnel => fail
}

func TestVerifyIsolationCmd_MissingTo(t *testing.T) {
	saveRestoreGlobals(t)
	isolationTo = ""
	if err := verifyIsolationCmd.RunE(verifyIsolationCmd, nil); err == nil {
		t.Fatal("expected --to required error")
	}
}

func TestVerifyIsolationCmd_Loopback(t *testing.T) {
	saveRestoreGlobals(t)
	isolationFrom = "lan"
	isolationTo = "127.0.0.1"
	timeout = "10s"
	jsonOutput = true
	outputPath = filepath.Join(t.TempDir(), "out.json")
	err := verifyIsolationCmd.RunE(verifyIsolationCmd, nil)
	requireExitCode(t, err, 1) // loopback reachable => isolation violated
}

func TestVerifyIsolationCmd_LoopbackHuman(t *testing.T) {
	saveRestoreGlobals(t)
	isolationFrom = "lan"
	isolationTo = "127.0.0.1"
	timeout = "10s"
	err := verifyIsolationCmd.RunE(verifyIsolationCmd, nil)
	requireExitCode(t, err, 1)
}

func TestVerifyIsolationCmd_PingError(t *testing.T) {
	saveRestoreGlobals(t)
	isolationFrom = "lan"
	isolationTo = "10.255.255.1"
	timeout = "1ms" // context cancels mid-ping => warn branch
	err := verifyIsolationCmd.RunE(verifyIsolationCmd, nil)
	requireExitCode(t, err, 3)
}

// ---------------------------------------------------------------------------
// verify-isolation --from honored via spec (#192)
// ---------------------------------------------------------------------------

func isolationSpec(t *testing.T, lanCIDR, lanGateway string) string {
	t.Helper()
	return writeSpec(t, fmt.Sprintf(`version: 1
site: test
networks:
  - name: lan
    cidr: %s
    gateway: %s
    zone: lan
  - name: iot
    cidr: 10.253.0.0/24
    gateway: 127.0.0.1
    zone: iot
`, lanCIDR, lanGateway))
}

func TestVerifyIsolationCmd_Spec_FromRequired(t *testing.T) {
	saveRestoreGlobals(t)
	specFile = isolationSpec(t, "192.0.2.0/24", "192.0.2.1")
	isolationFrom = ""
	isolationTo = "iot"
	timeout = "10s"
	err := verifyIsolationCmd.RunE(verifyIsolationCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "--from is required") {
		t.Fatalf("expected --from required error, got %v", err)
	}
}

func TestVerifyIsolationCmd_Spec_UnknownFromZone(t *testing.T) {
	saveRestoreGlobals(t)
	specFile = isolationSpec(t, "192.0.2.0/24", "192.0.2.1")
	isolationFrom = "bogus"
	isolationTo = "iot"
	timeout = "10s"
	err := verifyIsolationCmd.RunE(verifyIsolationCmd, nil)
	if err == nil || !strings.Contains(err.Error(), `source zone "bogus" is not declared`) {
		t.Fatalf("expected unknown-zone error, got %v", err)
	}
}

func TestVerifyIsolationCmd_Spec_RunnerOutsideFromZone(t *testing.T) {
	// The from-zone is TEST-NET, which this host can never be inside of, so
	// the engine must refuse a definitive verdict even though the to-zone
	// gateway is reachable. Before #192 the --from value was ignored and this
	// produced a hard fail (exit 1) from the local vantage point.
	saveRestoreGlobals(t)
	specFile = isolationSpec(t, "192.0.2.0/24", "192.0.2.1")
	isolationFrom = "lan"
	isolationTo = "iot"
	timeout = "10s"
	jsonOutput = true
	outputPath = filepath.Join(t.TempDir(), "iso.json")
	err := verifyIsolationCmd.RunE(verifyIsolationCmd, nil)
	requireExitCode(t, err, 3) // unconfirmed from outside the source zone
}

func TestVerifyIsolationCmd_Spec_RunnerInsideFromZone(t *testing.T) {
	// The from-zone wraps this host's own address, so the engine's runner
	// context places it inside the source zone and the verdict is definitive:
	// the to-zone gateway is loopback, which is reachable on every platform,
	// so isolation is violated.
	saveRestoreGlobals(t)
	ip := hostIPv4(t)
	specFile = isolationSpec(t, ip+"/32", ip)
	isolationFrom = "lan"
	isolationTo = "iot"
	timeout = "10s"
	jsonOutput = true
	outputPath = filepath.Join(t.TempDir(), "iso.json")
	err := verifyIsolationCmd.RunE(verifyIsolationCmd, nil)
	requireExitCode(t, err, 1) // violation confirmed from inside the source zone
}

func TestVerifyIsolationCmd_Spec_BadSpecFile(t *testing.T) {
	saveRestoreGlobals(t)
	specFile = filepath.Join(t.TempDir(), "missing.yaml")
	isolationFrom = "lan"
	isolationTo = "iot"
	timeout = "10s"
	err := verifyIsolationCmd.RunE(verifyIsolationCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "loading spec") {
		t.Fatalf("expected spec-loading error, got %v", err)
	}
}

func TestVerifyIsolationCmd_UnreachableTarget(t *testing.T) {
	// Without a spec, --from is a label and an unreachable target must not
	// error the command: Linux/darwin report "not reachable" as a pass
	// (exit 0), while Windows ping exits nonzero and produces a warn
	// (exit 3). Either verdict is correct for its platform.
	saveRestoreGlobals(t)
	specFile = ""
	isolationFrom = "lan"
	isolationTo = "192.0.2.1"
	timeout = "5s"
	err := verifyIsolationCmd.RunE(verifyIsolationCmd, nil)
	if err == nil {
		return
	}
	var exitErr *ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("unexpected error: %v", err)
	}
	if exitErr.Code != 3 {
		t.Errorf("exit code = %d, want 0 (linux/darwin) or 3 (windows)", exitErr.Code)
	}
}

// hostIPv4 returns any non-loopback IPv4 address on this host, mirroring the
// engine's runner-context enumeration.
func hostIPv4(t *testing.T) string {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipnet.IP.To4()
			if ip == nil || ip.IsLoopback() {
				continue
			}
			return ip.String()
		}
	}
	t.Fatal("no non-loopback IPv4 address found on this host")
	return ""
}

func TestDiscoverCmd_MissingSubnet(t *testing.T) {
	saveRestoreGlobals(t)
	discoverSubnet = ""
	if err := discoverCmd.RunE(discoverCmd, nil); err == nil {
		t.Fatal("expected --subnet required error")
	}
}

func TestDiscoverCmd_InvalidSubnet(t *testing.T) {
	saveRestoreGlobals(t)
	discoverSubnet = "not-a-cidr"
	// Fails at nmap.CheckAvailable on CI (no nmap) or at ParseCIDR locally.
	if err := discoverCmd.RunE(discoverCmd, nil); err == nil {
		t.Fatal("expected error for invalid subnet")
	}
}

// ---------------------------------------------------------------------------
// doctor / audit / interfaces command error paths
// ---------------------------------------------------------------------------

func TestDoctorCmd_HappyPath(t *testing.T) {
	if !nmap.Available() {
		t.Skip("nmap not available — doctor exits 2 in CI")
	}
	saveRestoreGlobals(t)
	specFile = writeSpec(t, "version: 1\nsite: test\n")
	outputPath = filepath.Join(t.TempDir(), "doctor.txt")
	if err := doctorCmd.RunE(doctorCmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDoctorCmd_JSON(t *testing.T) {
	if !nmap.Available() {
		t.Skip("nmap not available — doctor exits 2 in CI")
	}
	saveRestoreGlobals(t)
	jsonOutput = true
	if err := doctorCmd.RunE(doctorCmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDoctorCmd_JSON_FailingChecks(t *testing.T) {
	if nmap.Available() {
		t.Skip("nmap present — this test exercises the failing-doctor path")
	}
	saveRestoreGlobals(t)
	jsonOutput = true
	outputPath = filepath.Join(t.TempDir(), "doctor.json")
	err := doctorCmd.RunE(doctorCmd, nil)
	requireExitCode(t, err, 1) // missing nmap => fail
}

func TestDoctorCmd_Human_FailingChecks(t *testing.T) {
	if nmap.Available() {
		t.Skip("nmap present — this test exercises the failing-doctor path")
	}
	saveRestoreGlobals(t)
	outputPath = filepath.Join(t.TempDir(), "doctor.txt")
	err := doctorCmd.RunE(doctorCmd, nil)
	requireExitCode(t, err, 1) // missing nmap => fail => exit 1 (was hardcoded 2)
}

// TestDoctorCmd_NoHome_NoPanic ensures the log-directory check survives an
// unset HOME/USERPROFILE (regression for #133: out-of-range slice panic).
func TestDoctorCmd_NoHome_NoPanic(t *testing.T) {
	saveRestoreGlobals(t)
	outputPath = filepath.Join(t.TempDir(), "doctor.txt")
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	err := doctorCmd.RunE(doctorCmd, nil)
	if nmap.Available() {
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	} else {
		requireExitCode(t, err, 1)
	}
}

func TestInitCmd_BadInterface(t *testing.T) {
	saveRestoreGlobals(t)
	interfaceOpt = "__bogus_iface__"
	if err := initCmd.RunE(initCmd, nil); err == nil {
		t.Fatal("expected error for unknown interface (or missing nmap in CI)")
	}
}

func TestInitCmd_InvalidTimeout(t *testing.T) {
	saveRestoreGlobals(t)
	timeout = "not-a-duration"
	if err := initCmd.RunE(initCmd, nil); err == nil {
		t.Fatal("expected error for invalid --timeout (or missing nmap in CI)")
	}
}

func TestInitCmd_OutputError(t *testing.T) {
	saveRestoreGlobals(t)
	initOutput = t.TempDir() // a directory, not a file
	if err := initCmd.RunE(initCmd, nil); err == nil {
		t.Fatal("expected error creating output file (or missing nmap in CI)")
	}
}

func TestMcpServeCmd_InvalidTransport(t *testing.T) {
	saveRestoreGlobals(t)
	mcpTransport = "http"
	if err := mcpServeCmd.RunE(mcpServeCmd, nil); err == nil {
		t.Fatal("expected error for unsupported transport")
	}
}

func TestBuildCheckCmd_OutputError(t *testing.T) {
	registerFakeProvider(t)
	saveRestoreGlobals(t)
	cmd := buildCheckCmd(&fakeProvider{name: "fake"})
	providerHost = "10.0.0.5"
	outputPath = t.TempDir() // a directory, not a file
	if err := cmd.RunE(cmd, nil); err == nil {
		t.Fatal("expected error opening output file")
	}
}

func TestAuditCmd_NoSpec(t *testing.T) {
	saveRestoreGlobals(t)
	specFile = ""
	if err := auditCmd.RunE(auditCmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAuditCmd_InvalidSpec(t *testing.T) {
	saveRestoreGlobals(t)
	specFile = writeSpec(t, "version: 99\nsite: x\n")
	outputPath = filepath.Join(t.TempDir(), "out.json")
	jsonOutput = true
	err := auditCmd.RunE(auditCmd, nil)
	if err == nil {
		t.Fatal("expected error for invalid spec")
	}
}

func TestAuditCmd_InvalidTimeout(t *testing.T) {
	saveRestoreGlobals(t)
	specFile = writeSpec(t, "version: 1\nsite: test\n")
	timeout = "not-a-duration"
	err := auditCmd.RunE(auditCmd, nil)
	if err == nil {
		t.Fatal("expected invalid --timeout error")
	} else if !strings.Contains(err.Error(), "invalid --timeout") {
		t.Errorf("expected invalid --timeout error, got: %v", err)
	}
}

func TestCheckVPNCmd_InvalidExpect(t *testing.T) {
	saveRestoreGlobals(t)
	vpnTarget = "127.0.0.1"
	vpnExpect = "banana"
	timeout = "10s"
	err := checkVPNCmd.RunE(checkVPNCmd, nil)
	if err == nil {
		t.Fatal("expected invalid --expect error")
	} else if !strings.Contains(err.Error(), "invalid --expect") {
		t.Errorf("expected invalid --expect error, got: %v", err)
	}
}

func TestDiscoverCmd_InvalidTimeout(t *testing.T) {
	saveRestoreGlobals(t)
	discoverSubnet = "192.0.2.0/24"
	timeout = "not-a-duration"
	// Fails either at nmap.CheckAvailable (CI: no nmap) or --timeout parse.
	if err := discoverCmd.RunE(discoverCmd, nil); err == nil {
		t.Fatal("expected error for invalid --timeout")
	}
}

func TestAuditCmd_EmptySpec(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	saveRestoreGlobals(t)
	specFile = writeSpec(t, "version: 1\nsite: test\n")
	outputPath = filepath.Join(t.TempDir(), "out.json")
	jsonOutput = true
	if err := auditCmd.RunE(auditCmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if lastAuditReport == nil {
		t.Fatal("expected audit report to be cached")
	}
	// Human render path too.
	jsonOutput = false
	if err := auditCmd.RunE(auditCmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAuditCmd_JSONIncludesRecommendations(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	saveRestoreGlobals(t)
	// Isolation between two TEST-NET zones: the runner is not inside the
	// source zone, so the verdict is a WARN ("unconfirmed"). Warnings feed
	// the recommendations engine — a vantage_point recommendation must reach
	// the --json output (regression: recommendations were only generated on
	// the human path, so JSON reports never carried them).
	specFile = writeSpec(t, `version: 1
site: test
networks:
  - name: alpha
    cidr: 192.0.2.0/24
    gateway: 192.0.2.1
  - name: beta
    cidr: 198.51.100.0/24
    gateway: 198.51.100.1
assertions:
  - type: isolation
    from: alpha
    to: beta
    expect: deny
`)
	outPath := filepath.Join(t.TempDir(), "out.json")
	outputPath = outPath
	jsonOutput = true
	err := auditCmd.RunE(auditCmd, nil)
	requireExitCode(t, err, 3) // unconfirmed isolation => warn
	// Codacy false positive: outPath is created under t.TempDir(), not from user input.
	data, readErr := os.ReadFile(outPath) // nosemgrep: go_filesystem_rule-fileread
	if readErr != nil {
		t.Fatalf("reading audit output: %v", readErr)
	}
	var report models.AuditReport
	if umErr := json.Unmarshal(data, &report); umErr != nil {
		t.Fatalf("audit output is not valid JSON: %v", umErr)
	}
	if len(report.Recommendations) == 0 {
		t.Fatal("expected recommendations in JSON output, got none")
	}
	found := false
	for _, r := range report.Recommendations {
		if r.Category == "vantage_point" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected a vantage_point recommendation, got %+v", report.Recommendations)
	}

	// The human path must render the recommendations too.
	jsonOutput = false
	outputPath = ""
	err = auditCmd.RunE(auditCmd, nil)
	requireExitCode(t, err, 3)
}

func TestInterfacesCmd_NoSpec(t *testing.T) {
	saveRestoreGlobals(t)
	specFile = ""
	outputPath = filepath.Join(t.TempDir(), "ifaces.txt")
	listInterfacesCmd.SetContext(context.Background())
	if err := listInterfacesCmd.RunE(listInterfacesCmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInterfacesCmd_WithSpec(t *testing.T) {
	saveRestoreGlobals(t)
	specFile = writeSpec(t, "version: 1\nsite: test\nnetworks:\n  - name: lan\n    cidr: 192.168.1.0/24\n")
	outputPath = filepath.Join(t.TempDir(), "ifaces.txt")
	listInterfacesCmd.SetContext(context.Background())
	if err := listInterfacesCmd.RunE(listInterfacesCmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInterfacesCmd_BadSpec(t *testing.T) {
	saveRestoreGlobals(t)
	specFile = filepath.Join(t.TempDir(), "missing.yaml")
	listInterfacesCmd.SetContext(context.Background())
	if err := listInterfacesCmd.RunE(listInterfacesCmd, nil); err == nil {
		t.Fatal("expected error for missing spec")
	}
}

// ---------------------------------------------------------------------------
// snapshot / drift command wiring
// ---------------------------------------------------------------------------

func TestSnapshotBaselineCmd_NoAudit(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	saveRestoreGlobals(t)
	lastAuditReport = nil
	if err := snapshotBaselineCmd.RunE(snapshotBaselineCmd, nil); err == nil {
		t.Fatal("expected error without prior audit or saved snapshots")
	}
}

func TestSnapshotBaselineCmd_NoHome(t *testing.T) {
	saveRestoreGlobals(t)
	lastAuditReport = nil
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	if err := snapshotBaselineCmd.RunE(snapshotBaselineCmd, nil); err == nil {
		t.Fatal("expected error without a resolvable home directory")
	}
}

func TestSnapshotBaselineCmd_CorruptSnapshotFallback(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	saveRestoreGlobals(t)
	lastAuditReport = nil
	dir := filepath.Join(home, ".nyx", "snapshots")
	// Directories need execute permission for traversal; 0700 restricts access to the owner.
	if err := os.MkdirAll(dir, 0700); err != nil { // nosemgrep: go.lang.correctness.permissions.file_permission.incorrect-default-permission
		t.Fatalf("MkdirAll: %v", err)
	}
	// Newest snapshot is corrupt JSON — the fallback must surface the error.
	if err := os.WriteFile(filepath.Join(dir, "snapshot-20250601-140000.001.json"), []byte("{not json"), 0600); err != nil {
		t.Fatalf("writing corrupt snapshot: %v", err)
	}
	err := snapshotBaselineCmd.RunE(snapshotBaselineCmd, nil)
	if err == nil {
		t.Fatal("expected error loading corrupt snapshot")
	}
	if !strings.Contains(err.Error(), "loading most recent snapshot") {
		t.Errorf("expected snapshot-loading error, got: %v", err)
	}
}

func TestSnapshotBaselineCmd_FallsBackToSavedSnapshot(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	saveRestoreGlobals(t)
	lastAuditReport = nil
	report := &models.AuditReport{Status: models.StatusPass, Summary: models.ReportSummary{Pass: 1}}
	if _, err := snapshot.Save("test.spec", report); err != nil {
		t.Fatalf("saving snapshot: %v", err)
	}
	// Cross-process flow: no in-memory audit, but a snapshot exists on disk —
	// baseline must fall back to the most recent one instead of erroring.
	if err := snapshotBaselineCmd.RunE(snapshotBaselineCmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	baseline, err := snapshot.LoadBaseline()
	if err != nil {
		t.Fatalf("loading baseline: %v", err)
	}
	if baseline.SpecPath != "test.spec" {
		t.Errorf("expected baseline spec test.spec, got %q", baseline.SpecPath)
	}
	if baseline.Status != models.StatusPass {
		t.Errorf("expected baseline status pass, got %s", baseline.Status)
	}
}

func TestSnapshotBaselineCmd_RestoreFromFile(t *testing.T) {
	// Need a saved snapshot in a temp HOME (snapshot.Dir uses os.UserHomeDir,
	// which reads USERPROFILE on Windows).
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	saveRestoreGlobals(t)
	report := &models.AuditReport{Status: models.StatusPass, Summary: models.ReportSummary{Pass: 1}}
	snapPath, err := snapshot.Save("test.spec", report)
	if err != nil {
		t.Fatalf("saving snapshot: %v", err)
	}
	if err := snapshotBaselineCmd.RunE(snapshotBaselineCmd, []string{snapPath}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSnapshotBaselineCmd_FromLastAudit(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	saveRestoreGlobals(t)
	specFile = "test.spec"
	lastAuditReport = &models.AuditReport{
		Status:  models.StatusPass,
		Summary: models.ReportSummary{Pass: 1},
		Findings: []models.CheckResult{
			{CheckType: "route_check", Target: "127.0.0.1", Status: models.StatusPass, StartedAt: time.Now()},
		},
	}
	if err := snapshotBaselineCmd.RunE(snapshotBaselineCmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSnapshotListCmd_WithSnapshots(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	report := &models.AuditReport{Status: models.StatusPass}
	if _, err := snapshot.Save("test.spec", report); err != nil {
		t.Fatalf("saving snapshot: %v", err)
	}
	if err := snapshotListCmd.RunE(snapshotListCmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSnapshotDeleteCmd_All(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	// Empty dir first: "No snapshots to delete".
	if err := snapshotDeleteCmd.RunE(snapshotDeleteCmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	report := &models.AuditReport{Status: models.StatusPass}
	if _, err := snapshot.Save("test.spec", report); err != nil {
		t.Fatalf("saving snapshot: %v", err)
	}
	if err := snapshotDeleteCmd.RunE(snapshotDeleteCmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDriftStatusCmd_Clean(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	saveRestoreGlobals(t)
	specFile = "test.spec"
	finding := models.CheckResult{CheckType: "route_check", Target: "127.0.0.1", Status: models.StatusPass, Summary: "ok"}
	report := &models.AuditReport{
		Status:   models.StatusPass,
		Summary:  models.ReportSummary{Pass: 1},
		Findings: []models.CheckResult{finding},
	}
	if err := snapshot.SetBaseline(specFile, report); err != nil {
		t.Fatalf("setting baseline: %v", err)
	}
	lastAuditReport = report // identical findings => no drift, no os.Exit
	out := captureStdout(func() {
		if err := driftStatusCmd.RunE(driftStatusCmd, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(out, "All good") {
		t.Errorf("expected clean drift report, got: %s", out)
	}
}

func TestDriftCompareCmd(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	report := &models.AuditReport{
		Status:  models.StatusFail,
		Summary: models.ReportSummary{Pass: 0, Fail: 1},
		Findings: []models.CheckResult{
			{CheckType: "route_check", Target: "10.0.0.1", Status: models.StatusFail, Summary: "no route"},
		},
	}
	a, err := snapshot.Save("a.spec", report)
	if err != nil {
		t.Fatalf("saving snapshot: %v", err)
	}
	ok := &models.AuditReport{Status: models.StatusPass, Summary: models.ReportSummary{Pass: 1}}
	b, err := snapshot.Save("b.spec", ok)
	if err != nil {
		t.Fatalf("saving snapshot: %v", err)
	}
	// driftCompareCmd joins args onto the snapshots dir, so pass basenames.
	out := captureStdout(func() {
		if err := driftCompareCmd.RunE(driftCompareCmd, []string{filepath.Base(a), filepath.Base(b)}); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	if !strings.Contains(out, "Drift Report") {
		t.Errorf("expected drift report, got: %s", out)
	}
}

func TestSnapshotListCmd_Empty(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if err := snapshotListCmd.RunE(snapshotListCmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSnapshotDeleteCmd_SpecificMissing(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if err := snapshotDeleteCmd.RunE(snapshotDeleteCmd, []string{"nope.json"}); err == nil {
		t.Fatal("expected error deleting missing snapshot")
	}
}

func TestSnapshotClearBaselineCmd_NoBaseline(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if err := snapshotClearBaselineCmd.RunE(snapshotClearBaselineCmd, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDriftStatusCmd_NoBaseline(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	lastAuditReport = nil
	err := driftStatusCmd.RunE(driftStatusCmd, nil)
	if err == nil {
		t.Fatal("expected error without baseline")
	}
}

func TestDriftStatusCmd_DriftDetected(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	saveRestoreGlobals(t)
	specFile = "test.spec"
	baseline := &models.AuditReport{
		Status:   models.StatusPass,
		Summary:  models.ReportSummary{Pass: 1},
		Findings: []models.CheckResult{{CheckType: "route_check", Target: "127.0.0.1", Status: models.StatusPass, Summary: "ok"}},
	}
	if err := snapshot.SetBaseline(specFile, baseline); err != nil {
		t.Fatalf("setting baseline: %v", err)
	}
	lastAuditReport = &models.AuditReport{
		Status:   models.StatusFail,
		Summary:  models.ReportSummary{Pass: 0, Fail: 1},
		Findings: []models.CheckResult{{CheckType: "route_check", Target: "127.0.0.1", Status: models.StatusFail, Summary: "no route"}},
	}
	err := driftStatusCmd.RunE(driftStatusCmd, nil)
	requireExitCode(t, err, 1) // new failure => drift => exit 1
}

func TestDriftStatusCmd_WarningsOnly(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	saveRestoreGlobals(t)
	specFile = "test.spec"
	baseline := &models.AuditReport{
		Status:   models.StatusPass,
		Summary:  models.ReportSummary{Pass: 1},
		Findings: []models.CheckResult{{CheckType: "route_check", Target: "127.0.0.1", Status: models.StatusPass, Summary: "ok"}},
	}
	if err := snapshot.SetBaseline(specFile, baseline); err != nil {
		t.Fatalf("setting baseline: %v", err)
	}
	// A warning on a brand-new check (key absent from baseline) is a new warning,
	// which alone must exit 3.
	lastAuditReport = &models.AuditReport{
		Status:  models.StatusWarn,
		Summary: models.ReportSummary{Pass: 0, Warn: 1},
		Findings: []models.CheckResult{
			{CheckType: "port_check", Target: "10.0.0.9", Status: models.StatusWarn, Summary: "no snmp"},
		},
	}
	err := driftStatusCmd.RunE(driftStatusCmd, nil)
	requireExitCode(t, err, 3) // new warnings only => exit 3
}
