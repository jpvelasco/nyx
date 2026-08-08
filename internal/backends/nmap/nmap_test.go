package nmap

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jpvelasco/nyx/internal/models"
)

func TestPoliteScanOptionsDefaults(t *testing.T) {
	opts := PoliteScanOptions
	if opts.TimingTemplate != 2 {
		t.Errorf("expected TimingTemplate 2, got %d", opts.TimingTemplate)
	}
	if opts.MinRate != 50 {
		t.Errorf("expected MinRate 50, got %d", opts.MinRate)
	}
	if opts.MaxRate != 100 {
		t.Errorf("expected MaxRate 100, got %d", opts.MaxRate)
	}
}

func TestScanOptionsForMode(t *testing.T) {
	if ScanOptionsForMode("polite") != PoliteScanOptions {
		t.Error("polite should return PoliteScanOptions")
	}
	if ScanOptionsForMode("normal") != DefaultScanOptions {
		t.Error("normal should return DefaultScanOptions")
	}
	if ScanOptionsForMode("unknown") != PoliteScanOptions {
		t.Error("unknown mode should default to polite")
	}
	aggressive := ScanOptionsForMode("aggressive")
	if aggressive.TimingTemplate != 5 {
		t.Errorf("aggressive should be T5, got T%d", aggressive.TimingTemplate)
	}
}

func TestPortScanResultShape(t *testing.T) {
	if !Available() {
		t.Skip("nmap not available")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := PortScan(ctx, "192.0.2.1", []int{80, 443}, "tcp", PoliteScanOptions)
	if err != nil {
		t.Fatalf("PortScan returned error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.CheckType != "port_check" {
		t.Errorf("expected check_type 'port_check', got %q", result.CheckType)
	}
}

func TestPortScanResultShape_SingleOpenPort(t *testing.T) {
	if !Available() {
		t.Skip("nmap not available")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := PortScan(ctx, "127.0.0.1", []int{22}, "tcp", PoliteScanOptions)
	if err != nil {
		t.Fatalf("PortScan returned error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestPortScanResultShape_MultipleOpenPorts(t *testing.T) {
	if !Available() {
		t.Skip("nmap not available")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := PortScan(ctx, "127.0.0.1", []int{80, 443, 8080}, "tcp", PoliteScanOptions)
	if err != nil {
		t.Fatalf("PortScan returned error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestPortScanResultShape_AllFiltered(t *testing.T) {
	if !Available() {
		t.Skip("nmap not available")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := PortScan(ctx, "192.0.2.1", []int{80, 443}, "tcp", PoliteScanOptions)
	if err != nil {
		t.Fatalf("PortScan returned error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestPortScanResultShape_MixedStates(t *testing.T) {
	if !Available() {
		t.Skip("nmap not available")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	result, err := PortScan(ctx, "127.0.0.1", []int{22, 80, 443, 9999}, "tcp", PoliteScanOptions)
	if err != nil {
		t.Fatalf("PortScan returned error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestPortScanTimeout(t *testing.T) {
	if !Available() {
		t.Skip("nmap not available")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	_, err := PortScan(ctx, "192.0.2.1", []int{80}, "tcp", PoliteScanOptions)
	if err == nil {
		t.Error("expected timeout error")
	} else if !strings.Contains(err.Error(), "deadline exceeded") {
		t.Errorf("expected timeout-related error, got: %v", err)
	}
}

func TestPortScanMultipleHosts(t *testing.T) {
	if !Available() {
		t.Skip("nmap not available")
	}
	result, err := PortScan(context.Background(), "127.0.0.1", []int{22, 80, 443, 8080}, "tcp", DefaultScanOptions)
	if err != nil {
		t.Fatalf("PortScan error: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

// ─── parseNmapOutput tests ───

func TestParseNmapOutput_Empty(t *testing.T) {
	hosts := parseNmapOutput("")
	if hosts != nil {
		t.Fatalf("expected nil for empty output, got %d hosts", len(hosts))
	}
}

func TestParseNmapOutput_NoReportLines(t *testing.T) {
	hosts := parseNmapOutput("some random text\nno nmap output here\n")
	if hosts != nil {
		t.Fatalf("expected nil for non-nmap output, got %d hosts", len(hosts))
	}
}

func TestParseNmapOutput_SingleHostBareIP(t *testing.T) {
	output := `Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 10.0.20.1
Host is up (0.0023s latency).
MAC Address: AA:BB:CC:DD:EE:FF (Vendor Name)

Nmap done: 1 IP address (1 host up) scanned in 0.50 seconds`

	hosts := parseNmapOutput(output)
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(hosts))
	}
	h := hosts[0]
	if h.IP != "10.0.20.1" {
		t.Errorf("expected IP 10.0.20.1, got %s", h.IP)
	}
	if h.Hostname != "" {
		t.Errorf("expected empty hostname, got %s", h.Hostname)
	}
	if h.Status != "up" {
		t.Errorf("expected status 'up', got %s", h.Status)
	}
	if h.MAC != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("expected MAC AA:BB:CC:DD:EE:FF, got %s", h.MAC)
	}
}

func TestParseNmapOutput_SingleHostWithHostname(t *testing.T) {
	output := `Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for gateway.local (10.0.20.1)
Host is up (0.0023s latency).
MAC Address: 00:11:22:33:44:55 (Cisco)

Nmap done: 1 IP address (1 host up) scanned in 0.50 seconds`

	hosts := parseNmapOutput(output)
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(hosts))
	}
	h := hosts[0]
	if h.IP != "10.0.20.1" {
		t.Errorf("expected IP 10.0.20.1, got %s", h.IP)
	}
	if h.Hostname != "gateway.local" {
		t.Errorf("expected hostname 'gateway.local', got %s", h.Hostname)
	}
	if h.MAC != "00:11:22:33:44:55" {
		t.Errorf("expected MAC 00:11:22:33:44:55, got %s", h.MAC)
	}
}

func TestParseNmapOutput_MultipleHosts(t *testing.T) {
	output := `Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 10.0.20.1
Host is up (0.0023s latency).
MAC Address: AA:BB:CC:DD:EE:01 (Vendor1)

Nmap scan report for workstation.local (10.0.20.5)
Host is up (0.0045s latency).
MAC Address: aa:bb:cc:dd:ee:05 (Vendor2)

Nmap scan report for 10.0.20.10
Host is up (0.0010s latency).

Nmap done: 256 IP addresses (3 hosts up) scanned in 2.10 seconds`

	hosts := parseNmapOutput(output)
	if len(hosts) != 3 {
		t.Fatalf("expected 3 hosts, got %d", len(hosts))
	}

	// First host: bare IP with MAC
	if hosts[0].IP != "10.0.20.1" {
		t.Errorf("host 0: expected IP 10.0.20.1, got %s", hosts[0].IP)
	}
	if hosts[0].MAC != "AA:BB:CC:DD:EE:01" {
		t.Errorf("host 0: expected MAC AA:BB:CC:DD:EE:01, got %s", hosts[0].MAC)
	}

	// Second host: hostname + IP with MAC (lowercase MAC should be uppercased)
	if hosts[1].Hostname != "workstation.local" {
		t.Errorf("host 1: expected hostname 'workstation.local', got %s", hosts[1].Hostname)
	}
	if hosts[1].IP != "10.0.20.5" {
		t.Errorf("host 1: expected IP 10.0.20.5, got %s", hosts[1].IP)
	}
	if hosts[1].MAC != "AA:BB:CC:DD:EE:05" {
		t.Errorf("host 1: expected MAC AA:BB:CC:DD:EE:05 (uppercased), got %s", hosts[1].MAC)
	}

	// Third host: bare IP, no MAC
	if hosts[2].IP != "10.0.20.10" {
		t.Errorf("host 2: expected IP 10.0.20.10, got %s", hosts[2].IP)
	}
	if hosts[2].MAC != "" {
		t.Errorf("host 2: expected empty MAC, got %s", hosts[2].MAC)
	}
}

func TestParseNmapOutput_HostNoUpLine(t *testing.T) {
	// A host report without "Host is up" — should get "unknown" status
	output := `Nmap scan report for 10.0.20.99

Nmap done: 1 IP address (0 hosts up) scanned in 0.10 seconds`

	hosts := parseNmapOutput(output)
	if len(hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(hosts))
	}
	if hosts[0].Status != "unknown" {
		t.Errorf("expected status 'unknown', got %s", hosts[0].Status)
	}
}

// ─── parseHostBlock tests ───

func TestParseHostBlock_Nil(t *testing.T) {
	h := parseHostBlock("no report line here")
	if h != nil {
		t.Fatal("expected nil for block without report line")
	}
}

func TestParseHostBlock_BareIP(t *testing.T) {
	block := `Nmap scan report for 192.168.1.1
Host is up (0.0010s latency).`
	h := parseHostBlock(block)
	if h == nil {
		t.Fatal("expected non-nil host")
	}
	if h.IP != "192.168.1.1" {
		t.Errorf("expected IP 192.168.1.1, got %s", h.IP)
	}
	if h.Hostname != "" {
		t.Errorf("expected empty hostname, got %s", h.Hostname)
	}
	if h.Status != "up" {
		t.Errorf("expected status 'up', got %s", h.Status)
	}
}

func TestParseHostBlock_HostnameAndIP(t *testing.T) {
	block := `Nmap scan report for myrouter (192.168.1.1)
Host is up (0.0010s latency).
MAC Address: DE:AD:BE:EF:00:01 (RouterVendor)`
	h := parseHostBlock(block)
	if h == nil {
		t.Fatal("expected non-nil host")
	}
	if h.Hostname != "myrouter" {
		t.Errorf("expected hostname 'myrouter', got %s", h.Hostname)
	}
	if h.IP != "192.168.1.1" {
		t.Errorf("expected IP 192.168.1.1, got %s", h.IP)
	}
	if h.MAC != "DE:AD:BE:EF:00:01" {
		t.Errorf("expected MAC DE:AD:BE:EF:00:01, got %s", h.MAC)
	}
}

func TestParseHostBlock_NoMAC(t *testing.T) {
	block := `Nmap scan report for 10.10.10.10
Host is up.`
	h := parseHostBlock(block)
	if h == nil {
		t.Fatal("expected non-nil host")
	}
	if h.MAC != "" {
		t.Errorf("expected empty MAC, got %s", h.MAC)
	}
}

func TestParseHostBlock_MACLowercaseInput(t *testing.T) {
	// MAC should be uppercased even when input is lowercase
	block := `Nmap scan report for 10.10.10.10
Host is up.
MAC Address: aa:bb:cc:dd:ee:ff (Test)`
	h := parseHostBlock(block)
	if h == nil {
		t.Fatal("expected non-nil host")
	}
	if h.MAC != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("expected uppercased MAC AA:BB:CC:DD:EE:FF, got %s", h.MAC)
	}
}

// ─── discoveryVerdict / discoverySummary tests (#127) ───

func TestDiscoveryVerdict(t *testing.T) {
	tests := []struct {
		name      string
		hostCount int
		scanErr   error
		want      models.Status
	}{
		{"clean scan with hosts passes", 5, nil, models.StatusPass},
		{"empty clean scan warns", 0, nil, models.StatusWarn},
		{"partial scan with nonzero exit keeps warn", 5, fmt.Errorf("nmap exited with warning: exit status 1"), models.StatusWarn},
		{"failed empty scan warns", 0, fmt.Errorf("boom"), models.StatusWarn},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := discoveryVerdict(tt.hostCount, tt.scanErr); got != tt.want {
				t.Errorf("discoveryVerdict(%d, %v) = %s, want %s", tt.hostCount, tt.scanErr, got, tt.want)
			}
		})
	}
}

func TestDiscoverySummary(t *testing.T) {
	if got := discoverySummary(0, "10.0.0.0/24"); got != "no hosts discovered in 10.0.0.0/24" {
		t.Errorf("empty summary = %q", got)
	}
	if got := discoverySummary(3, "10.0.0.0/24"); got != "discovered 3 host(s) in 10.0.0.0/24" {
		t.Errorf("hosts summary = %q", got)
	}
}

// ─── parsePortScanOutput tests ───

func TestParsePortScanOutput_AllOpen(t *testing.T) {
	output := `Nmap scan report for 127.0.0.1
Host is up.
PORT     STATE  SERVICE
22/tcp   open   ssh
80/tcp   open   http
443/tcp  open   https`

	states := parsePortScanOutput(output, []int{22, 80, 443}, "tcp")
	if len(states) != 3 {
		t.Fatalf("expected 3 port states, got %d", len(states))
	}
	for _, ps := range states {
		if ps.State != "open" {
			t.Errorf("port %d: expected state 'open', got %s", ps.Port, ps.State)
		}
		if ps.Protocol != "tcp" {
			t.Errorf("port %d: expected protocol 'tcp', got %s", ps.Port, ps.Protocol)
		}
	}
}

func TestParsePortScanOutput_MixedStates(t *testing.T) {
	output := `Nmap scan report for 192.168.1.1
Host is up.
PORT     STATE    SERVICE
22/tcp   open     ssh
80/tcp   filtered http
443/tcp  open     https`

	states := parsePortScanOutput(output, []int{22, 80, 443, 8080}, "tcp")
	if len(states) != 4 {
		t.Fatalf("expected 4 port states, got %d", len(states))
	}
	expected := map[int]string{22: "open", 80: "filtered", 443: "open", 8080: "filtered"}
	for _, ps := range states {
		want := expected[ps.Port]
		if ps.State != want {
			t.Errorf("port %d: expected state %q, got %s", ps.Port, want, ps.State)
		}
	}
}

func TestParsePortScanOutput_AllFiltered(t *testing.T) {
	// No port lines found — all requested ports should be "filtered"
	output := `Nmap scan report for 10.0.0.1
Host is up.`

	states := parsePortScanOutput(output, []int{80, 443}, "tcp")
	if len(states) != 2 {
		t.Fatalf("expected 2 port states, got %d", len(states))
	}
	for _, ps := range states {
		if ps.State != "filtered" {
			t.Errorf("port %d: expected state 'filtered', got %s", ps.Port, ps.State)
		}
	}
}

func TestParsePortScanOutput_UDPProtocol(t *testing.T) {
	output := `Nmap scan report for 10.0.0.1
Host is up.
PORT     STATE  SERVICE
53/udp   open   domain
161/udp  open   snmp`

	states := parsePortScanOutput(output, []int{53, 161, 123}, "udp")
	if len(states) != 3 {
		t.Fatalf("expected 3 port states, got %d", len(states))
	}
	if states[0].State != "open" {
		t.Errorf("port 53: expected 'open', got %s", states[0].State)
	}
	if states[1].State != "open" {
		t.Errorf("port 161: expected 'open', got %s", states[1].State)
	}
	if states[2].State != "filtered" {
		t.Errorf("port 123: expected 'filtered', got %s", states[2].State)
	}
	for _, ps := range states {
		if ps.Protocol != "udp" {
			t.Errorf("expected protocol 'udp', got %s", ps.Protocol)
		}
	}
}

func TestParsePortScanOutput_WithClosedState(t *testing.T) {
	output := `Nmap scan report for 10.0.0.1
Host is up.
PORT     STATE    SERVICE
22/tcp   open     ssh
80/tcp   closed   http`

	states := parsePortScanOutput(output, []int{22, 80}, "tcp")
	if len(states) != 2 {
		t.Fatalf("expected 2 port states, got %d", len(states))
	}
	if states[0].State != "open" {
		t.Errorf("port 22: expected 'open', got %s", states[0].State)
	}
	if states[1].State != "closed" {
		t.Errorf("port 80: expected 'closed', got %s", states[1].State)
	}
}

func TestParsePortScanOutput_EmptyOutput(t *testing.T) {
	states := parsePortScanOutput("", []int{80, 443}, "tcp")
	if len(states) != 2 {
		t.Fatalf("expected 2 port states, got %d", len(states))
	}
	for _, ps := range states {
		if ps.State != "filtered" {
			t.Errorf("expected 'filtered' for empty output, got %s", ps.State)
		}
	}
}

// ─── Discover tests (no nmap required) ───

func TestDiscover_InvalidCIDR(t *testing.T) {
	result, err := Discover(context.Background(), "not-a-cidr")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
	if result.Status != "error" {
		t.Errorf("expected status 'error', got %s", result.Status)
	}
	if result.CheckType != "subnet_discovery" {
		t.Errorf("expected check_type 'subnet_discovery', got %s", result.CheckType)
	}
	if result.Tool != "nmap" {
		t.Errorf("expected tool 'nmap', got %s", result.Tool)
	}
}

func TestDiscover_InvalidCIDRNotAnIP(t *testing.T) {
	result, err := Discover(context.Background(), "hello/world")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if err == nil {
		t.Fatal("expected error")
	}
	if result.Status != "error" {
		t.Errorf("expected status 'error', got %s", result.Status)
	}
}

func TestDiscoverWithOptions_InvalidCIDR(t *testing.T) {
	result, err := DiscoverWithOptions(context.Background(), "999.999.999.999/24", PoliteScanOptions)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
	if result.Status != "error" {
		t.Errorf("expected status 'error', got %s", result.Status)
	}
}

func TestDiscover_ValidCIDR_NoNmap(t *testing.T) {
	if Available() {
		t.Skip("nmap is available — this test requires nmap to be absent")
	}
	result, err := Discover(context.Background(), "192.168.1.0/24")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if err == nil {
		t.Fatal("expected error when nmap is not installed")
	}
	if result.Status != "error" {
		t.Errorf("expected status 'error', got %s", result.Status)
	}
}

func TestDiscoverWithOptions_ValidCIDR_NoNmap(t *testing.T) {
	if Available() {
		t.Skip("nmap is available — this test requires nmap to be absent")
	}
	result, err := DiscoverWithOptions(context.Background(), "10.0.0.0/8", DefaultScanOptions)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if err == nil {
		t.Fatal("expected error when nmap is not installed")
	}
	if result.Status != "error" {
		t.Errorf("expected status 'error', got %s", result.Status)
	}
}

// ─── Discover happy path (requires nmap) ───

func TestDiscover_HappyPath_Loopback(t *testing.T) {
	if !Available() {
		t.Skip("nmap not available")
	}
	// Scan loopback — should find at least 1 host
	result, err := Discover(context.Background(), "127.0.0.1/32")
	if err != nil {
		t.Fatalf("Discover failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Status != "pass" {
		t.Errorf("expected status 'pass', got %s", result.Status)
	}
	if result.CheckType != "subnet_discovery" {
		t.Errorf("expected check_type 'subnet_discovery', got %s", result.CheckType)
	}
	if result.Tool != "nmap" {
		t.Errorf("expected tool 'nmap', got %s", result.Tool)
	}
	// Verify hosts were discovered
	hosts, ok := result.Observed["hosts"]
	if !ok {
		t.Fatal("expected 'hosts' in Observed")
	}
	hostSlice, ok := hosts.([]Host)
	if !ok {
		t.Fatalf("expected hosts to be []Host, got %T", hosts)
	}
	if len(hostSlice) == 0 {
		t.Error("expected at least 1 host on loopback")
	}
	// Verify total
	if result.Observed["total"] == nil {
		t.Fatal("expected 'total' in Observed")
	}
	// Evidence should contain raw nmap output
	if len(result.Evidence) == 0 {
		t.Error("expected evidence to contain raw nmap output")
	}
	// Duration should be set
	if result.DurationMs <= 0 {
		t.Error("expected positive duration")
	}
}

func TestDiscoverWithOptions_HappyPath(t *testing.T) {
	if !Available() {
		t.Skip("nmap not available")
	}
	result, err := DiscoverWithOptions(context.Background(), "127.0.0.1/32", PoliteScanOptions)
	if err != nil {
		t.Fatalf("DiscoverWithOptions failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Status != "pass" {
		t.Errorf("expected status 'pass', got %s", result.Status)
	}
	// Summary should mention host count
	if result.Summary == "" {
		t.Error("expected non-empty summary")
	}
}

func TestDiscoverWithTimeout_HappyPath(t *testing.T) {
	if !Available() {
		t.Skip("nmap not available")
	}
	result, err := DiscoverWithTimeout(context.Background(), "127.0.0.1/32", 30*time.Second)
	if err != nil {
		t.Fatalf("DiscoverWithTimeout failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Status != "pass" {
		t.Errorf("expected status 'pass', got %s", result.Status)
	}
}

// ─── DiscoverWithTimeout tests ───

func TestDiscoverWithTimeout_InvalidCIDR(t *testing.T) {
	result, err := DiscoverWithTimeout(context.Background(), "bad-cidr", 5*time.Second)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
	if result.Status != "error" {
		t.Errorf("expected status 'error', got %s", result.Status)
	}
}

func TestDiscoverWithTimeout_ContextTimeout(t *testing.T) {
	if !Available() {
		t.Skip("nmap not available")
	}
	// Use a very short timeout — nmap won't finish in 50ms
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	result, err := DiscoverWithTimeout(ctx, "192.0.2.0/24", 50*time.Millisecond)
	if err == nil {
		t.Error("expected timeout error")
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Status != "error" {
		t.Errorf("expected status 'error', got %s", result.Status)
	}
}

// ─── Available tests ───

func TestAvailable_ReturnsBool(_ *testing.T) {
	// Just verify it returns a bool (true or false) — no assertions on value
	// since nmap may or may not be installed
	_ = Available()
}

func TestAvailable_Idempotent(t *testing.T) {
	a := Available()
	b := Available()
	if a != b {
		t.Errorf("Available() should be idempotent: %v != %v", a, b)
	}
}

// ─── CheckAvailable tests ───

func TestCheckAvailable_WhenAvailable(t *testing.T) {
	if Available() {
		err := CheckAvailable()
		if err != nil {
			t.Errorf("expected nil when nmap is available, got: %v", err)
		}
	} else {
		t.Skip("nmap not available — cannot test the nil-return path")
	}
}

func TestCheckAvailable_WhenNotAvailable(t *testing.T) {
	if !Available() {
		err := CheckAvailable()
		if err == nil {
			t.Fatal("expected error when nmap is not available")
		}
		errMsg := err.Error()
		if !strings.Contains(errMsg, "nmap is required") {
			t.Errorf("expected error to mention 'nmap is required', got: %s", errMsg)
		}
		if !strings.Contains(errMsg, "Install it with") {
			t.Errorf("expected error to mention install instructions, got: %s", errMsg)
		}
	} else {
		t.Skip("nmap is available — cannot test the error path")
	}
}

// ─── installCmd tests ───

func TestInstallCmd_ReturnsNonEmpty(t *testing.T) {
	cmd := installCmd()
	if cmd == "" {
		t.Error("installCmd() returned empty string")
	}
}

func TestInstallCmd_ContainsInstall(t *testing.T) {
	cmd := installCmd()
	if !strings.Contains(cmd, "install") && !strings.Contains(cmd, "add") {
		t.Errorf("expected install command to contain 'install' or 'add', got: %s", cmd)
	}
}

func TestInstallCmd_ContainsNmap(t *testing.T) {
	cmd := installCmd()
	if !strings.Contains(cmd, "nmap") {
		t.Errorf("expected install command to mention 'nmap', got: %s", cmd)
	}
}

func TestInstallCmdFor(t *testing.T) {
	notFound := func(string) error { return errors.New("not found") }
	tests := []struct {
		name   string
		goos   string
		lookup func(bin string) error
		want   string
	}{
		{"windows", "windows", notFound, "winget install nmap"},
		{"darwin", "darwin", notFound, "brew install nmap"},
		{"linux apt-get", "linux", only("apt-get"), "sudo apt-get install -y nmap"},
		{"linux apt", "linux", only("apt"), "sudo apt install -y nmap"},
		{"linux dnf", "linux", only("dnf"), "sudo dnf install -y nmap"},
		{"linux yum", "linux", only("yum"), "sudo yum install -y nmap"},
		{"linux pacman", "linux", only("pacman"), "sudo pacman -S nmap"},
		{"linux apk", "linux", only("apk"), "sudo apk add nmap"},
		{"linux none", "linux", notFound, "sudo <your-package-manager> install nmap"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := installCmdFor(tc.goos, tc.lookup); got != tc.want {
				t.Errorf("installCmdFor(%q) = %q, want %q", tc.goos, got, tc.want)
			}
		})
	}
}

func only(bin string) func(string) error {
	return func(b string) error {
		if b == bin {
			return nil
		}
		return errors.New("not found")
	}
}

func TestDiscoverWithOptions_NmapNotFound(t *testing.T) {
	t.Setenv("PATH", "")
	result, err := DiscoverWithOptions(context.Background(), "10.0.0.0/8", DefaultScanOptions)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if err == nil {
		t.Fatal("expected error when nmap is not installed")
	}
	if result.Status != "error" {
		t.Errorf("expected status 'error', got %s", result.Status)
	}
	if !strings.Contains(result.Summary, "not installed") {
		t.Errorf("expected summary to mention nmap not installed, got: %s", result.Summary)
	}
	if !strings.Contains(err.Error(), "Install it with") {
		t.Errorf("expected error to include install instructions, got: %s", err.Error())
	}
}

func TestPortScan_NmapNotFound(t *testing.T) {
	t.Setenv("PATH", "")
	result, err := PortScan(context.Background(), "127.0.0.1", []int{80}, "tcp", PoliteScanOptions)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if err == nil {
		t.Fatal("expected error when nmap is not installed")
	}
	if result.Status != "error" {
		t.Errorf("expected status 'error', got %s", result.Status)
	}
}

func TestCheckAvailable_NmapNotFound(t *testing.T) {
	t.Setenv("PATH", "")
	err := CheckAvailable()
	if err == nil {
		t.Fatal("expected error when nmap is not in PATH")
	}
	if !strings.Contains(err.Error(), "Install it with") {
		t.Errorf("expected error to include install instructions, got: %s", err.Error())
	}
}

func TestDiscoverWithOptions_ZeroOptions(t *testing.T) {
	if !Available() {
		t.Skip("nmap not available")
	}
	result, err := DiscoverWithOptions(context.Background(), "127.0.0.1/32", ScanOptions{})
	if err != nil {
		t.Fatalf("DiscoverWithOptions with zero options failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Status != "pass" {
		t.Errorf("expected status 'pass', got %s", result.Status)
	}
}

func TestPortScan_EmptyPorts(t *testing.T) {
	if !Available() {
		t.Skip("nmap not available")
	}
	result, err := PortScan(context.Background(), "127.0.0.1", []int{}, "tcp", PoliteScanOptions)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if err == nil {
		t.Fatal("expected error for empty ports")
	}
	if result.Status != "error" {
		t.Errorf("expected status 'error', got %s", result.Status)
	}
	if !strings.Contains(result.Summary, "no ports") {
		t.Errorf("expected summary to mention empty ports, got: %s", result.Summary)
	}
}

func TestPortScan_UDP(t *testing.T) {
	if !Available() {
		t.Skip("nmap not available")
	}
	result, err := PortScan(context.Background(), "127.0.0.1", []int{53}, "udp", PoliteScanOptions)
	if err != nil {
		t.Fatalf("PortScan udp failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestPortScan_ZeroOptions(t *testing.T) {
	if !Available() {
		t.Skip("nmap not available")
	}
	result, err := PortScan(context.Background(), "127.0.0.1", []int{22}, "tcp", ScanOptions{})
	if err != nil {
		t.Fatalf("PortScan with zero options failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestParsePortScanOutput_OverflowPortIgnored(t *testing.T) {
	output := `Nmap scan report for 10.0.0.1
Host is up.
PORT     STATE  SERVICE
99999999999999/tcp   open   http
22/tcp   open   ssh`

	states := parsePortScanOutput(output, []int{22, 80}, "tcp")
	if len(states) != 2 {
		t.Fatalf("expected 2 port states, got %d", len(states))
	}
	if states[0].State != "open" {
		t.Errorf("port 22: expected 'open', got %s", states[0].State)
	}
	if states[1].State != "filtered" {
		t.Errorf("port 80: expected 'filtered' (overflow line ignored), got %s", states[1].State)
	}
}

// ─── ScanMode constant tests ───

func TestScanModeConstants(t *testing.T) {
	if ScanModePolite != "polite" {
		t.Errorf("expected ScanModePolite = 'polite', got %q", ScanModePolite)
	}
	if ScanModeNormal != "normal" {
		t.Errorf("expected ScanModeNormal = 'normal', got %q", ScanModeNormal)
	}
	if ScanModeAggressive != "aggressive" {
		t.Errorf("expected ScanModeAggressive = 'aggressive', got %q", ScanModeAggressive)
	}
}

func TestScanOptionsForMode_Aggressive(t *testing.T) {
	opts := ScanOptionsForMode(ScanModeAggressive)
	if opts.TimingTemplate != 5 {
		t.Errorf("aggressive should be T5, got T%d", opts.TimingTemplate)
	}
}

func TestScanOptionsForMode_Normal(t *testing.T) {
	opts := ScanOptionsForMode(ScanModeNormal)
	if opts != DefaultScanOptions {
		t.Errorf("normal should return DefaultScanOptions")
	}
}

func TestScanOptionsForMode_Polite(t *testing.T) {
	opts := ScanOptionsForMode(ScanModePolite)
	if opts != PoliteScanOptions {
		t.Errorf("polite should return PoliteScanOptions")
	}
}

func TestScanOptionsForMode_EmptyString(t *testing.T) {
	opts := ScanOptionsForMode("")
	if opts != PoliteScanOptions {
		t.Errorf("empty mode should default to PoliteScanOptions")
	}
}

// ─── DiscoveryResult JSON tests ───

func TestDiscoveryResult_JSONMarshaling(t *testing.T) {
	dr := DiscoveryResult{
		Hosts: []Host{
			{IP: "10.0.0.1", Hostname: "router", Status: "up", MAC: "AA:BB:CC:DD:EE:01"},
			{IP: "10.0.0.2", Status: "up"},
		},
		Total: 2,
	}
	data, err := json.Marshal(dr)
	if err != nil {
		t.Fatalf("failed to marshal DiscoveryResult: %v", err)
	}
	var decoded DiscoveryResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if decoded.Total != 2 {
		t.Errorf("expected total 2, got %d", decoded.Total)
	}
	if len(decoded.Hosts) != 2 {
		t.Errorf("expected 2 hosts, got %d", len(decoded.Hosts))
	}
}

// ─── PortScan edge cases (no nmap needed) ───

func TestPortScan_EmptyPorts_NoNmap(t *testing.T) {
	if Available() {
		t.Skip("nmap is available — this test requires nmap to be absent for the nmap-not-found path, but we test empty ports which is checked before nmap lookup")
	}
	result, err := PortScan(context.Background(), "127.0.0.1", []int{}, "tcp", PoliteScanOptions)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if err == nil {
		t.Fatal("expected error for empty ports")
	}
	if result.Status != "error" {
		t.Errorf("expected status 'error', got %s", result.Status)
	}
}

// ─── reReport regex tests ───

func TestReReport_BareIP(t *testing.T) {
	matches := reReport.FindAllStringSubmatch(
		"Nmap scan report for 10.0.20.1", -1)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	// Group 3 = bare IP
	if matches[0][3] != "10.0.20.1" {
		t.Errorf("expected IP 10.0.20.1, got %s", matches[0][3])
	}
}

func TestReReport_HostnameWithIP(t *testing.T) {
	matches := reReport.FindAllStringSubmatch(
		"Nmap scan report for myhost.local (192.168.1.1)", -1)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	// Group 1 = hostname, Group 2 = IP
	if matches[0][1] != "myhost.local" {
		t.Errorf("expected hostname 'myhost.local', got %s", matches[0][1])
	}
	if matches[0][2] != "192.168.1.1" {
		t.Errorf("expected IP 192.168.1.1, got %s", matches[0][2])
	}
}

func TestReReport_NoMatch(t *testing.T) {
	matches := reReport.FindAllStringSubmatch("random text", -1)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matches))
	}
}

// ─── reUp regex tests ───

func TestReUp_Match(t *testing.T) {
	if !reUp.MatchString("Host is up (0.0023s latency).") {
		t.Error("expected match for 'Host is up'")
	}
	if !reUp.MatchString("Host is up.") {
		t.Error("expected match for 'Host is up.'")
	}
}

func TestReUp_NoMatch(t *testing.T) {
	if reUp.MatchString("Host is down") {
		t.Error("expected no match for 'Host is down'")
	}
	if reUp.MatchString("") {
		t.Error("expected no match for empty string")
	}
}

// ─── reMAC regex tests ───

func TestReMAC_Match(t *testing.T) {
	m := reMAC.FindStringSubmatch("MAC Address: AA:BB:CC:DD:EE:FF (Vendor)")
	if m == nil {
		t.Fatal("expected MAC match")
	}
	if m[1] != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("expected MAC AA:BB:CC:DD:EE:FF, got %s", m[1])
	}
}

func TestReMAC_Lowercase(t *testing.T) {
	m := reMAC.FindStringSubmatch("MAC Address: aa:bb:cc:dd:ee:ff (Vendor)")
	if m == nil {
		t.Fatal("expected MAC match for lowercase")
	}
	if m[1] != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("expected lowercase MAC, got %s", m[1])
	}
}

func TestReMAC_NoMatch(t *testing.T) {
	m := reMAC.FindStringSubmatch("no mac here")
	if m != nil {
		t.Error("expected no match")
	}
}

// ─── rePortLine regex tests ───

func TestRePortLine_Match(t *testing.T) {
	m := rePortLine.FindStringSubmatch("22/tcp   open  ssh")
	if m == nil {
		t.Fatal("expected port line match")
	}
	if m[1] != "22" {
		t.Errorf("expected port '22', got %s", m[1])
	}
	if m[2] != "tcp" {
		t.Errorf("expected protocol 'tcp', got %s", m[2])
	}
	if m[3] != "open" {
		t.Errorf("expected state 'open', got %s", m[3])
	}
}

func TestRePortLine_UDP(t *testing.T) {
	m := rePortLine.FindStringSubmatch("53/udp   open|filtered  domain")
	if m == nil {
		t.Fatal("expected UDP port line match")
	}
	if m[1] != "53" {
		t.Errorf("expected port '53', got %s", m[1])
	}
	if m[2] != "udp" {
		t.Errorf("expected protocol 'udp', got %s", m[2])
	}
}

func TestRePortLine_NoMatch(t *testing.T) {
	m := rePortLine.FindStringSubmatch("this is not a port line")
	if m != nil {
		t.Error("expected no match for non-port line")
	}
}

// ─── Host struct JSON tests ───

func TestHost_JSONMarshaling(t *testing.T) {
	h := Host{IP: "10.0.0.1", Hostname: "test", Status: "up", MAC: "AA:BB:CC:DD:EE:FF"}
	data, err := json.Marshal(h)
	if err != nil {
		t.Fatalf("failed to marshal Host: %v", err)
	}
	var decoded Host
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal Host: %v", err)
	}
	if decoded.IP != h.IP {
		t.Errorf("IP mismatch: %s != %s", decoded.IP, h.IP)
	}
	if decoded.Hostname != h.Hostname {
		t.Errorf("Hostname mismatch: %s != %s", decoded.Hostname, h.Hostname)
	}
}

// ─── PortScanResult JSON tests ───

func TestPortScanResult_JSONMarshaling(t *testing.T) {
	psr := PortScanResult{
		Ports: []PortState{
			{Port: 22, Protocol: "tcp", State: "open"},
			{Port: 80, Protocol: "tcp", State: "filtered"},
		},
	}
	data, err := json.Marshal(psr)
	if err != nil {
		t.Fatalf("failed to marshal PortScanResult: %v", err)
	}
	var decoded PortScanResult
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal PortScanResult: %v", err)
	}
	if len(decoded.Ports) != 2 {
		t.Errorf("expected 2 ports, got %d", len(decoded.Ports))
	}
}
