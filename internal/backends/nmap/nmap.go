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

	// "Nmap done: 256 IP addresses (12 hosts up) scanned in 3.42s"
	reDone = regexp.MustCompile(`(?m)^Nmap done: (\d+) IP address(?:es)? \((\d+) hosts? up\) scanned`)
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
	// ProbeSet selects the host-discovery probe set for discovery scans.
	// The zero value keeps nmap's default probe set.
	ProbeSet ProbeSet
}

// ProbeSet selects the host-discovery probe set for discovery scans.
type ProbeSet string

const (
	// ProbeSetDefault keeps nmap's default host-discovery probes. On hosts
	// with raw-socket access that set includes an ICMP timestamp request,
	// which edge-gateway attack-defense may classify as an attack.
	ProbeSetDefault ProbeSet = ""
	// ProbeSetARP uses ARP ping only. It requires a directly-attached
	// subnet and generates no IP probes.
	ProbeSetARP ProbeSet = "arp"
	// ProbeSetICMP uses an ICMP echo request only.
	ProbeSetICMP ProbeSet = "icmp"
)

// ParseProbeSet converts a user-supplied probe set name to a ProbeSet.
// The empty string and "default" both keep nmap's default probe set.
func ParseProbeSet(s string) (ProbeSet, error) {
	switch s {
	case "":
		return ProbeSetDefault, nil
	case "arp":
		return ProbeSetARP, nil
	case "icmp":
		return ProbeSetICMP, nil
	case "default":
		return ProbeSetDefault, nil
	}
	return ProbeSetDefault, fmt.Errorf("unknown probe set %q (want arp, icmp, or default)", s)
}

// flag returns the nmap host-discovery flag for the probe set, or the empty
// string when the probe set stays nmap's default.
func (p ProbeSet) flag() string {
	switch p {
	case ProbeSetARP:
		return "-PR"
	case ProbeSetICMP:
		return "-PE"
	}
	return ""
}

// DirectlyAttached reports whether the local machine holds an IPv4 address
// inside the given CIDR. Only such subnets can be probed with ARP.
func DirectlyAttached(cidr string) (bool, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return false, fmt.Errorf("reading network interfaces: %w", err)
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
			ipNet, ok := a.(*net.IPNet)
			if !ok || ipNet.IP.To4() == nil {
				continue
			}
			if ipnet.Contains(ipNet.IP) {
				return true, nil
			}
		}
	}
	return false, nil
}

// ChooseProbeSet selects ARP for directly-attached subnets and ICMP echo for
// routed ones, so a sweep never relies on nmap's default probe set.
func ChooseProbeSet(cidr string) (ProbeSet, error) {
	attached, err := DirectlyAttached(cidr)
	if err != nil {
		return ProbeSetDefault, err
	}
	if attached {
		return ProbeSetARP, nil
	}
	return ProbeSetICMP, nil
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

// runNmap executes nmap and classifies the outcome:
//
//   - clean: exit 0; out is nmap's stdout
//   - warn: non-zero exit but stdout was produced (for example "no hosts
//     found"); out is still usable and err carries the exit status
//   - hard: context cancellation, or non-zero exit with empty stdout; out is
//     empty and err explains the failure, including nmap's stderr so the
//     cause (for example "need root to do a UDP scan") is visible
func runNmap(ctx context.Context, nmapPath string, args []string) (out string, err error, warned bool) {
	cmd := exec.CommandContext(ctx, nmapPath, args...) // nosemgrep
	var stderr strings.Builder
	cmd.Stderr = &stderr
	stdout, runErr := cmd.Output()
	if runErr == nil {
		return string(stdout), nil, false
	}
	if ctx.Err() != nil {
		return "", ctx.Err(), false
	}
	if len(stdout) == 0 {
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return "", fmt.Errorf("nmap error: %w: %s", runErr, detail), false
		}
		return "", fmt.Errorf("nmap error: %w", runErr), false
	}
	return string(stdout), runErr, true
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

	// Build args: nmap -sn [-PR|-PE] [-Tn] [--min-rate N] [--max-rate N] <cidr>
	args := buildDiscoverArgs(opts, cidr)
	out, err, warned := runNmap(ctx, nmapPath, args)
	if err != nil && !warned {
		// Context cancellation manifests as an error here
		if ctx.Err() != nil {
			result.Status = models.StatusError
			result.Summary = fmt.Sprintf("nmap timed out or was cancelled: %v", ctx.Err())
			result.Finish()
			return result, ctx.Err()
		}
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("nmap exited with error: %v", err)
		result.Finish()
		return result, err
	}
	if warned {
		result.Status = models.StatusWarn
		result.Summary = fmt.Sprintf("nmap exited with warning: %v", err)
	}

	hosts := parseNmapOutput(out)
	done := parseDoneLine(out)

	dr := DiscoveryResult{
		Hosts: hosts,
		Total: len(hosts),
	}

	// Serialise into Observed so the generic report machinery can use it
	result.Observed = map[string]interface{}{
		"hosts": dr.Hosts,
		"total": dr.Total,
	}
	if done != nil {
		result.Observed["addresses_scanned"] = done.Addresses
		result.Observed["hosts_up"] = done.HostsUp
		result.Observed["unresponsive"] = unresponsiveFrom(done)
	}

	result.Status = discoveryVerdict(len(hosts), err)
	result.Summary = discoverySummary(len(hosts), unresponsiveFrom(done), cidr)

	// Attach raw nmap output as evidence
	result.Evidence = append(result.Evidence, strings.TrimSpace(out))

	result.Finish()
	return result, nil
}

// discoveryVerdict decides the final status of a discovery scan after
// parsing. A nonzero nmap exit leaves the WARN already set for the failed
// run — a partial scan must not upgrade to pass — while an empty-but-
// successful scan stays a warning. Only a clean scan with hosts passes.
func discoveryVerdict(hostCount int, scanErr error) models.Status {
	if scanErr != nil || hostCount == 0 {
		return models.StatusWarn
	}
	return models.StatusPass
}

// doneLine is nmap's final scan summary, for example
// "Nmap done: 256 IP addresses (12 hosts up) scanned in 3.42s".
type doneLine struct {
	Addresses int
	HostsUp   int
}

// parseDoneLine reads the final summary line from raw nmap output. It
// returns nil when the line is absent (nmap failed before finishing).
func parseDoneLine(output string) *doneLine {
	m := reDone.FindStringSubmatch(output)
	if m == nil {
		return nil
	}
	addresses, err := strconv.Atoi(m[1])
	if err != nil {
		return nil
	}
	hostsUp, err := strconv.Atoi(m[2])
	if err != nil {
		return nil
	}
	return &doneLine{Addresses: addresses, HostsUp: hostsUp}
}

// unresponsiveFrom counts addresses that produced no host-discovery
// response. Those are down or probes filtered — reported separately from
// the discovered host list, which only contains responders.
func unresponsiveFrom(done *doneLine) int {
	if done == nil {
		return 0
	}
	if n := done.Addresses - done.HostsUp; n > 0 {
		return n
	}
	return 0
}

// buildDiscoverArgs assembles the nmap argument list for a ping sweep.
func buildDiscoverArgs(opts ScanOptions, cidr string) []string {
	args := []string{"-sn"}
	if pf := opts.ProbeSet.flag(); pf != "" {
		args = append(args, pf)
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
	return append(args, cidr)
}

// buildPortScanArgs assembles the nmap argument list for a port scan.
func buildPortScanArgs(opts ScanOptions, target string, ports []int, protocol string) []string {
	portList := make([]string, len(ports))
	for i, p := range ports {
		portList[i] = fmt.Sprintf("%d", p)
	}

	// -Pn skips host discovery: the target is already a known host, and
	// re-discovery would re-send the probe set at every target.
	args := []string{"-sV", "--open", "-Pn"}
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
	return append(args, "-p", strings.Join(portList, ","), target)
}

// discoverySummary renders the human summary line for a discovery result.
func discoverySummary(hostCount, unresponsive int, cidr string) string {
	suffix := ""
	if unresponsive > 0 {
		suffix = fmt.Sprintf(" — %d addresses unresponsive: down or probes filtered", unresponsive)
	}
	if hostCount == 0 {
		return fmt.Sprintf("no hosts discovered in %s%s", cidr, suffix)
	}
	return fmt.Sprintf("discovered %d host(s) in %s%s", hostCount, cidr, suffix)
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

	args := buildPortScanArgs(opts, target, ports, protocol)

	out, err, warned := runNmap(ctx, nmapPath, args)
	if err != nil && !warned {
		if ctx.Err() != nil {
			result.Status = models.StatusError
			result.Summary = fmt.Sprintf("nmap timed out: %v", ctx.Err())
			result.Finish()
			return result, ctx.Err()
		}
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("nmap exited with error: %v", err)
		result.Finish()
		return result, err
	}
	if warned {
		result.Status = models.StatusWarn
		result.Summary = fmt.Sprintf("nmap exited with warning: %v", err)
	}

	portStates := parsePortScanOutput(out, ports, protocol)

	psJSON, _ := json.Marshal(PortScanResult{Ports: portStates})
	var psMap map[string]interface{}
	_ = json.Unmarshal(psJSON, &psMap)
	result.Observed = psMap
	result.Evidence = append(result.Evidence, strings.TrimSpace(out))

	if err == nil {
		result.Status = models.StatusPass
	}
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
