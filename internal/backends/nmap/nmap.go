// Package nmap provides a backend for subnet host discovery using the nmap tool.
package nmap

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/velasco-jp/netaudit/internal/models"
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

// Available reports whether nmap is installed on the current system.
func Available() bool {
	_, err := exec.LookPath("nmap")
	return err == nil
}

// Discover runs an nmap ping sweep over the given CIDR and returns a CheckResult
// containing the list of discovered hosts.
//
// The supplied context controls the maximum run time; callers should set a
// deadline before calling this function for untrusted or large ranges.
func Discover(ctx context.Context, cidr string) (*models.CheckResult, error) {
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
		result.Status = models.StatusError
		result.Summary = "nmap is not installed or not in PATH"
		result.Finish()
		return result, fmt.Errorf("nmap not found: %w", err)
	}

	// Run: nmap -sn <cidr>
	cmd := exec.CommandContext(ctx, nmapPath, "-sn", cidr)
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
