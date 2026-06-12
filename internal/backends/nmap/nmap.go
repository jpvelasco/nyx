// Package nmap provides a backend for subnet host discovery using the nmap tool.
package nmap

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jpvelasco/nyx/internal/models"
)

// Host represents a discovered network host.
type Host struct {
	IP       string `json:"ip"`
	Hostname string `json:"hostname,omitempty"`
	Status   string `json:"status"`
	MAC      string `json:"mac,omitempty"`
}

// DiscoveryResult holds the list of hosts found during a scan.
type DiscoveryResult struct {
	Hosts []Host `json:"hosts"`
	Total int    `json:"total"`
}

// regular expressions for parsing nmap -sn output
var (
	// "Nmap scan report for 10.0.20.1"
	// "Nmap scan report for hostname.local (10.0.20.5)"
	reReport = regexp.MustCompile(
		`(?m)^Nmap scan report for (?:(\S+) \((\d+\.\d+\.\d+\.\d+)\)|(\d+\.\d+\.\d+\.\d+))`)

	// "Host is up (0.0023s latency)."
	reUp = regexp.MustCompile(`(?m)^Host is up`)

	// "MAC Address: AA:BB:CC:DD:EE:FF (Vendor Name)"
	reMAC = regexp.MustCompile(`(?m)^MAC Address: ([0-9A-Fa-f:]{17})`)
)

// ScanOptions controls nmap scan behaviour.
type ScanOptions struct {
	// TimingTemplate sets the nmap -T flag (0-5). Default 4.
	// Higher values are faster but more aggressive.
	TimingTemplate int
	// MinRate sets --min-rate (packets/sec). 0 means use nmap default.
	// 500 is a good balance between speed and IDS friendliness.
	MinRate int
	// MaxRate sets --max-rate (packets/sec). 0 means no limit.
	MaxRate int
}

// PoliteScanOptions is safe for use on SDN controllers with flood detection.
// Equivalent to nmap -T2 --min-rate 50 --max-rate 100.
var PoliteScanOptions = ScanOptions{
	TimingTemplate: 2,
	MinRate:        50,
	MaxRate:        100,
}

// DefaultScanOptions returns sensible defaults: -T4 --min-rate 500.
// This cuts scan time on quiet subnets from ~45s to ~7s.
var DefaultScanOptions = ScanOptions{
	TimingTemplate: 4,
	MinRate:        500,
}

// Available reports whether nmap is installed on the current system.
func Available() bool {
	_, err := exec.LookPath("nmap")
	return err == nil
}

// Discover runs an nmap ping sweep over the given CIDR and returns a CheckResult
// containing the list of discovered hosts. Uses DefaultScanOptions.
//
// The supplied context controls the maximum run time; callers should set a
// deadline before calling this function for untrusted or large ranges.
func Discover(ctx context.Context, cidr string) (*models.CheckResult, error) {
	return DiscoverWithOptions(ctx, cidr, DefaultScanOptions)
}

// DiscoverWithOptions runs an nmap ping sweep with explicit ScanOptions.
func DiscoverWithOptions(ctx context.Context, cidr string, opts ScanOptions) (*models.CheckResult, error) {
	result := models.NewCheckResult("nmap", "subnet_discovery", "nmap", cidr)

	// Validate CIDR
	if _, _, err := net.ParseCIDR(cidr); err != nil {
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("invalid CIDR %q: %v", cidr, err)
		result.Finish()
		return result, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}

	// Check that nmap is installed
	nmapPath, err := exec.LookPath("nmap")
	if err != nil {
		installErr := CheckAvailable()
		result.Status = models.StatusError
		result.Summary = "nmap is not installed or not in PATH"
		result.Finish()
		return result, installErr
	}

	// Build args: nmap -sn [-Tn] [--min-rate N] [--max-rate N] <cidr>
	args := []string{"-sn"}
	if opts.TimingTemplate > 0 {
		args = append(args, fmt.Sprintf("-T%d", opts.TimingTemplate))
	}
	if opts.MinRate > 0 {
		args = append(args, "--min-rate", fmt.Sprintf("%d", opts.MinRate))
	}
	if opts.MaxRate > 0 {
		args = append(args, "--max-rate", fmt.Sprintf("%d", opts.MaxRate))
	}
	args = append(args, cidr)
	cmd := exec.CommandContext(ctx, nmapPath, args...) // nosemgrep
	out, err := cmd.Output()
	if err != nil {
		// Context cancellation manifests as an error here
		if ctx.Err() != nil {
			result.Status = models.StatusError
			result.Summary = fmt.Sprintf("nmap timed out or was cancelled: %v", ctx.Err())
			result.Finish()
			return result, ctx.Err()
		}
		// nmap exits non-zero on some conditions (e.g. no hosts found) –
		// treat as a warning rather than a hard error when there is output.
		if len(out) == 0 {
			result.Status = models.StatusError
			result.Summary = fmt.Sprintf("nmap exited with error: %v", err)
			result.Finish()
			return result, fmt.Errorf("nmap error: %w", err)
		}
	}

	hosts := parseNmapOutput(string(out))

	dr := DiscoveryResult{
		Hosts: hosts,
		Total: len(hosts),
	}

	// Serialise into Observed so the generic report machinery can use it
	drJSON, _ := json.Marshal(dr)
	var drMap map[string]interface{}
	_ = json.Unmarshal(drJSON, &drMap)
	result.Observed = drMap

	result.Summary = fmt.Sprintf("discovered %d host(s) in %s", len(hosts), cidr)
	if len(hosts) == 0 {
		result.Status = models.StatusWarn
		result.Summary = fmt.Sprintf("no hosts discovered in %s", cidr)
	} else {
		result.Status = models.StatusPass
	}

	// Attach raw nmap output as evidence
	result.Evidence = append(result.Evidence, strings.TrimSpace(string(out)))

	result.Finish()
	return result, nil
}

// parseNmapOutput converts raw nmap -sn text into a slice of Host records.
func parseNmapOutput(output string) []Host {
	// Split output into per-host blocks on the "Nmap scan report for" boundary.
	// We keep the delimiter by using a lookahead-like split: find all match
	// positions and slice the string accordingly.
	matches := reReport.FindAllStringIndex(output, -1)
	if len(matches) == 0 {
		return nil
	}

	var hosts []Host
	for i, loc := range matches {
		var block string
		if i+1 < len(matches) {
			block = output[loc[0]:matches[i+1][0]]
		} else {
			block = output[loc[0]:]
		}

		host := parseHostBlock(block)
		if host != nil {
			hosts = append(hosts, *host)
		}
	}
	return hosts
}

// parseHostBlock extracts Host data from a single "Nmap scan report for …" block.
func parseHostBlock(block string) *Host {
	m := reReport.FindStringSubmatch(block)
	if m == nil {
		return nil
	}

	h := Host{}

	// Group 1 = hostname, Group 2 = IP  (hostname.local (10.0.20.5))
	// Group 3 = bare IP                 (10.0.20.1)
	if m[1] != "" {
		h.Hostname = m[1]
		h.IP = m[2]
	} else {
		h.IP = m[3]
	}

	if reUp.MatchString(block) {
		h.Status = "up"
	} else {
		h.Status = "unknown"
	}

	if mac := reMAC.FindStringSubmatch(block); mac != nil {
		h.MAC = strings.ToUpper(mac[1])
	}

	return &h
}

// DiscoverWithTimeout is a convenience wrapper around Discover that applies a
// fixed timeout to the context.
func DiscoverWithTimeout(parent context.Context, cidr string, timeout time.Duration) (*models.CheckResult, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	return Discover(ctx, cidr)
}

// ScanMode is a named preset for scan aggressiveness.
type ScanMode string

const (
	// ScanModePolite uses a slower, less intrusive scan timing (T2, min rate 100).
	ScanModePolite ScanMode = "polite"
	// ScanModeNormal uses default nmap timing (T3).
	ScanModeNormal ScanMode = "normal"
	// ScanModeAggressive uses faster timing (T4, higher min rate).
	ScanModeAggressive ScanMode = "aggressive"
)

// ScanOptionsForMode returns the ScanOptions preset for a named mode.
// Unknown modes default to polite.
func ScanOptionsForMode(mode ScanMode) ScanOptions {
	switch mode {
	case ScanModeNormal:
		return DefaultScanOptions
	case ScanModeAggressive:
		return ScanOptions{TimingTemplate: 5}
	default:
		return PoliteScanOptions
	}
}

// PortState holds the observed state of a single port.
type PortState struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"` // "open", "closed", "filtered"
}

// PortScanResult holds per-port scan results.
type PortScanResult struct {
	Ports []PortState `json:"ports"`
}

// rePortLine matches nmap port lines like "80/tcp   open  http"
var rePortLine = regexp.MustCompile(`^(\d+)/(tcp|udp)\s+(\S+)`)

// PortScan scans specific ports on a target using nmap.
// protocol must be "tcp" or "udp".
func PortScan(ctx context.Context, target string, ports []int, protocol string, opts ScanOptions) (*models.CheckResult, error) {
	result := models.NewCheckResult("nmap", "port_check", "nmap", target)

	nmapPath, err := exec.LookPath("nmap")
	if err != nil {
		result.Status = models.StatusError
		result.Summary = "nmap is not installed or not in PATH"
		result.Finish()
		return result, CheckAvailable()
	}

	if len(ports) == 0 {
		result.Status = models.StatusError
		result.Summary = "no ports specified"
		result.Finish()
		return result, fmt.Errorf("ports list is empty")
	}

	portList := make([]string, len(ports))
	for i, p := range ports {
		portList[i] = fmt.Sprintf("%d", p)
	}

	args := []string{"-sV", "--open"}
	if protocol == "udp" {
		args = append(args, "-sU")
	} else {
		args = append(args, "-sT")
	}
	if opts.TimingTemplate > 0 {
		args = append(args, fmt.Sprintf("-T%d", opts.TimingTemplate))
	}
	if opts.MinRate > 0 {
		args = append(args, "--min-rate", fmt.Sprintf("%d", opts.MinRate))
	}
	if opts.MaxRate > 0 {
		args = append(args, "--max-rate", fmt.Sprintf("%d", opts.MaxRate))
	}
	args = append(args, "-p", strings.Join(portList, ","), target)

	cmd := exec.CommandContext(ctx, nmapPath, args...) // nosemgrep
	out, err := cmd.Output()
	if err != nil {
		if ctx.Err() != nil {
			result.Status = models.StatusError
			result.Summary = fmt.Sprintf("nmap timed out: %v", ctx.Err())
			result.Finish()
			return result, ctx.Err()
		}
		if len(out) == 0 {
			result.Status = models.StatusError
			result.Summary = fmt.Sprintf("nmap exited with error: %v", err)
			result.Finish()
			return result, fmt.Errorf("nmap error: %w", err)
		}
	}

	portStates := parsePortScanOutput(string(out), ports, protocol)

	psJSON, _ := json.Marshal(PortScanResult{Ports: portStates})
	var psMap map[string]interface{}
	_ = json.Unmarshal(psJSON, &psMap)
	result.Observed = psMap
	result.Evidence = append(result.Evidence, strings.TrimSpace(string(out)))
	result.Status = models.StatusPass
	result.Summary = fmt.Sprintf("port scan of %s: %d ports checked", target, len(ports))
	result.Finish()
	return result, nil
}

// parsePortScanOutput parses nmap port scan output into PortState slice.
// Ports not found in output are reported as "filtered".
func parsePortScanOutput(output string, requested []int, protocol string) []PortState {
	found := make(map[int]string)
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		m := rePortLine.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		port64, err := strconv.ParseInt(m[1], 10, 32)
		if err != nil {
			continue
		}
		found[int(port64)] = m[3]
	}
	states := make([]PortState, len(requested))
	for i, p := range requested {
		state := "filtered"
		if s, ok := found[p]; ok {
			state = s
		}
		states[i] = PortState{Port: p, Protocol: protocol, State: state}
	}
	return states
}
