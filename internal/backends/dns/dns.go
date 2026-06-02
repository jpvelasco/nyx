package dns

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strings"

	"github.com/jpvelasco/nyx/internal/models"
)

// reDigStatus matches the dig response status line: ";; ->>HEADER<<- ... status: SERVFAIL"
var (
	reDigBogus     = regexp.MustCompile(`(?m);\s+status:\s+BOGUS`)
	reDigServFail  = regexp.MustCompile(`(?m);\s+status:\s+SERVFAIL`)
	reDigNoError   = regexp.MustCompile(`(?m);\s+status:\s+NOERROR`)
	reDigValidated = regexp.MustCompile(`(?m);\s+status:\s+VALIDATED`)
	// RRSIG records appear on their own line: "example.com. 300 IN RRSIG A ..."
	reRRSIG = regexp.MustCompile(`(?m)^\S+\s+\d+\s+IN\s+RRSIG\s`)
)

// resolve is the internal implementation, does not call Finish.
// Returns the CheckResult, list of resolved IPs, and any error.
func resolve(ctx context.Context, query, server string) (*models.CheckResult, []string, error) {
	result := models.NewCheckResult("dns", "dns_check", "dns", query)

	var ips []string

	if server == "" {
		// Use system default resolver
		addrs, err := net.DefaultResolver.LookupHost(ctx, query)
		if err != nil {
			result.Status = models.StatusError
			result.Summary = fmt.Sprintf("failed to resolve %s: %v", query, err)
			return result, nil, nil
		}
		ips = addrs
	} else {
		// Use custom resolver pointing at server:53
		resolver := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				// Wrap IPv6 addresses in brackets for host:port format
				serverAddr := server
				if strings.Contains(server, ":") && !strings.HasPrefix(server, "[") {
					serverAddr = "[" + server + "]"
				}
				d := net.Dialer{}
				return d.DialContext(ctx, "udp", serverAddr+":53")
			},
		}
		addrs, err := resolver.LookupHost(ctx, query)
		if err != nil {
			result.Status = models.StatusError
			result.Summary = fmt.Sprintf("failed to resolve %s (using %s): %v", query, server, err)
			return result, nil, nil
		}
		ips = addrs
	}

	// Successfully resolved
	result.Status = models.StatusPass
	result.Summary = fmt.Sprintf("resolved %s → [%s]", query, strings.Join(ips, ", "))

	result.Observed["ips"] = ips
	result.Observed["query"] = query
	result.Observed["server"] = server

	result.Evidence = append(result.Evidence, result.Summary)

	return result, ips, nil
}

// Resolve resolves a hostname using the specified or system resolver.
// Returns a CheckResult with the resolved IPs or error status.
func Resolve(ctx context.Context, query, server string) (*models.CheckResult, error) {
	result, _, _ := resolve(ctx, query, server)
	result.Finish()
	return result, nil
}

// ResolveExpect resolves a hostname and checks if the expected IP is in the results.
// Returns a CheckResult indicating pass if found, fail if not, or error if resolution failed.
func ResolveExpect(ctx context.Context, query, server, expectIP string) (*models.CheckResult, error) {
	result, ips, _ := resolve(ctx, query, server)

	// If resolution failed, return as-is
	if result.Status == models.StatusError {
		result.Finish()
		return result, nil
	}

	// Check if expectIP is in the resolved IPs
	found := false
	for _, ip := range ips {
		if ip == expectIP {
			found = true
			break
		}
	}

	if found {
		result.Status = models.StatusPass
		result.Summary = fmt.Sprintf("resolved %s → %s (matches expected)", query, expectIP)
	} else {
		result.Status = models.StatusFail
		result.Summary = fmt.Sprintf("resolved %s → [%s], expected %s", query, strings.Join(ips, ", "), expectIP)
		result.Violations = append(result.Violations, fmt.Sprintf("expected IP %s not in resolved addresses %v", expectIP, ips))
	}

	result.Expected["ip"] = expectIP
	result.Finish()
	return result, nil
}

// CheckAvailable checks if dig is available in PATH.
func CheckAvailable() error {
	_, err := exec.LookPath("dig")
	if err != nil {
		return fmt.Errorf("dig is not installed or not in PATH")
	}
	return nil
}

// Available returns true if dig is available in PATH.
func Available() bool {
	return CheckAvailable() == nil
}

// CheckDNSSEC validates the DNSSEC chain for a hostname.
// Uses dig +dnssec +sigchase to check DNSSEC validation.
func CheckDNSSEC(ctx context.Context, query, server string) (*models.CheckResult, error) {
	result := models.NewCheckResult("dig", "dns_check", "dns", query)

	// Check if dig is available
	if !Available() {
		result.Status = models.StatusError
		result.Summary = "dig is not installed or not in PATH"
		result.Evidence = append(result.Evidence, result.Summary)
		result.Finish()
		return result, nil
	}

	// Build dig command
	args := []string{"+dnssec", "+sigchase"}
	if server != "" {
		args = append([]string{"@" + server}, args...)
	}
	args = append(args, query)

	cmd := exec.CommandContext(ctx, "dig", args...)
	output, _ := cmd.CombinedOutput()
	outputStr := string(output)

	// Parse output for DNSSEC validation indicators using header-anchored patterns
	// to avoid false matches on domain names or record content.
	isValidated := reDigValidated.MatchString(outputStr)
	isNoError := reDigNoError.MatchString(outputStr)
	hasRRSIG := reRRSIG.MatchString(outputStr)
	isBogus := reDigBogus.MatchString(outputStr)
	isServFail := reDigServFail.MatchString(outputStr)

	// Determine result status
	if isBogus || isServFail {
		result.Status = models.StatusFail
		result.Summary = "DNSSEC validation failed - broken chain or unsigned response"
		result.Violations = append(result.Violations, "DNSSEC chain is broken or response is not properly signed")
	} else if isValidated || (isNoError && hasRRSIG) {
		result.Status = models.StatusPass
		result.Summary = "DNSSEC validation successful"
	} else if hasRRSIG {
		// Has signature records but no explicit validation
		result.Status = models.StatusPass
		result.Summary = "DNSSEC signature records present"
	} else {
		result.Status = models.StatusWarn
		result.Summary = "DNSSEC status could not be determined from dig output"
	}

	result.Observed["query"] = query
	result.Observed["server"] = server
	result.Evidence = append(result.Evidence, strings.Split(outputStr, "\n")...)

	result.Finish()
	return result, nil
}
