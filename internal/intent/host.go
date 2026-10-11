package intent

import (
	"fmt"
	"net"
	"strings"
)

// ValidateTarget validates a ping target or dig query. It must be a valid IP
// address or a plausible hostname, and it must not be shaped like a shell or
// tool option marker: values beginning with '-', '+', or '@' would be parsed
// as flags by ping (e.g. "-n") or dig (e.g. "+short", "@server"), so they are
// rejected to prevent option injection from spec or CLI/MCP input.
func ValidateTarget(s string) error {
	return validateNetworkTarget(s, "target", false)
}

// ValidateServer validates a dig server: a valid IP/hostname, optionally with
// an explicit ":port" (e.g. "10.0.10.1:5353" or "[::1]:53"). It applies the
// same option-marker rejection as ValidateTarget.
func ValidateServer(s string) error {
	return validateNetworkTarget(s, "server", true)
}

func validateNetworkTarget(s, kind string, allowPort bool) error {
	if strings.HasPrefix(s, "-") || strings.HasPrefix(s, "+") || strings.HasPrefix(s, "@") {
		return fmt.Errorf("%s %q must not start with '-', '+', or '@' (command-option-shaped value)", kind, s)
	}
	host := s
	if allowPort {
		// net.SplitHostPort understands both "host:port" and the
		// bracketed "[v6]:port" form; a bare "[v6]" literal has no
		// port and keeps its brackets for the IP check below.
		if h, _, err := net.SplitHostPort(s); err == nil {
			host = h
		} else if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
			host = s[1 : len(s)-1]
		}
	}
	// A single trailing dot marks an absolute (FQDN) name and is valid.
	host = strings.TrimSuffix(host, ".")
	if net.ParseIP(host) != nil {
		return nil
	}
	if !isValidHostname(host) {
		return fmt.Errorf("%s %q is neither a valid IP address nor a hostname", kind, s)
	}
	return nil
}

// isValidHostname reports whether s is a plausible DNS hostname: 1-253 chars
// of [A-Za-z0-9.-_] with no empty label and no label beginning or ending in a
// hyphen. It is deliberately permissive on character set (local/mDNS names
// use '_') while still catching whitespace, control characters, and
// flag-shaped values.
func isValidHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
		default:
			return false
		}
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}
	}
	return true
}
