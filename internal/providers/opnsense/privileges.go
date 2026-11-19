package opnsense

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

func opnsensePagePrivilege(path string) string {
	path = strings.TrimPrefix(path, "/")
	path = strings.TrimPrefix(path, "api/")
	path, _, _ = strings.Cut(path, "?")
	switch {
	case path == "firewall/filter/search_rule":
		return "Firewall: Rules [new]"
	case path == "diagnostics/firewall/log":
		return "Diagnostics: Logs: Firewall: Live View"
	case path == "diagnostics/firewall/stats":
		return "Diagnostics: Logs: Firewall: Summary View"
	case path == "core/system/status":
		return "System: Status"
	case path == "kea/leases4/search":
		return "Services: DHCP: Kea(v4)"
	case path == "kea/leases6/search":
		return "Services: DHCP: Kea(v6)"
	case path == "dnsmasq/leases/search", path == "dnsmasq/settings/get":
		return "Services: Dnsmasq DNS/DHCP: Settings"
	case strings.HasPrefix(path, "firewall/alias_util/"):
		return "Diagnostics: PF Table IP addresses"
	default:
		return ""
	}
}

// CheckPrivileges checks credentials and page access using read-only requests.
func (c *Client) CheckPrivileges(ctx context.Context) ([]string, error) {
	checks := []struct{ method, path string }{
		{http.MethodGet, "/firewall/alias/get"},
		{http.MethodPost, "/firewall/filter/search_rule"},
		{http.MethodGet, "/diagnostics/firewall/log?limit=1"},
		{http.MethodGet, "/core/system/status"},
		{http.MethodPost, "/kea/leases4/search"},
		{http.MethodPost, "/kea/leases6/search"},
		{http.MethodGet, "/dnsmasq/settings/get"},
		{http.MethodGet, "/firewall/alias_util/aliases"},
	}
	rows := make([]string, 0, len(checks))
	var problems []error
	for _, check := range checks {
		var body []byte
		if check.method == http.MethodPost {
			body = []byte(`{"current":1,"rowCount":1}`)
		}
		resp, err := c.do(ctx, check.method, check.path, body)
		if err == nil {
			drainBody(resp.Body)
			rows = append(rows, check.path+"\tusable")
			continue
		}
		var status *apiStatusError
		outcome := "check failed"
		if errors.As(err, &status) {
			switch status.code {
			case http.StatusUnauthorized:
				return rows, err
			case http.StatusForbidden:
				outcome = "blocked by privilege"
				if privilege := opnsensePagePrivilege(check.path); privilege != "" {
					outcome += " (" + privilege + ")"
				}
			case http.StatusNotFound:
				rows = append(rows, check.path+"\tmissing in this version")
				continue
			}
		}
		rows = append(rows, check.path+"\t"+outcome)
		problems = append(problems, err)
	}
	return rows, errors.Join(problems...)
}
