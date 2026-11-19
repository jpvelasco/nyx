package omada

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jpvelasco/nyx/internal/intent"
)

const (
	mdnsAvailable   = "available"
	mdnsUnavailable = "api-unavailable"
	mdnsUnknown     = "unknown"
)

// fetchMDNSInventory reads the documented site-level getMdnsGrid operation.
// The endpoint can be missing on particular controller builds. A rejected
// read leaves the actual configuration unknown, even when the UI exposes it.
func (c *Client) fetchMDNSInventory(ctx context.Context, siteID string) *intent.MDNSInventory {
	path := fmt.Sprintf("sites/%s/setting/service/mdns", siteID)
	rules, _, err := fetchPaged[intent.MDNSRule](ctx, c, path, defaultPageSize)
	if err == nil {
		if rules == nil {
			rules = []intent.MDNSRule{}
		}
		return &intent.MDNSInventory{Status: mdnsAvailable, Rules: rules}
	}
	var apiErr *apiError
	if errors.As(err, &apiErr) && apiErr.ErrorCode == -1600 {
		return &intent.MDNSInventory{Status: mdnsUnavailable}
	}
	return &intent.MDNSInventory{Status: mdnsUnknown}
}

func renderMDNSInventory(b *strings.Builder, inv *intent.MDNSInventory) {
	fmt.Fprintln(b, "\n== mDNS ==")
	switch inv.Status {
	case mdnsUnavailable:
		fmt.Fprintln(b, "  mdns: api-unavailable (UI-only; configuration unknown)")
	case mdnsUnknown:
		fmt.Fprintln(b, "  mdns: unknown (API read failed)")
	case mdnsAvailable:
		fmt.Fprintf(b, "  %d rule%s\n", len(inv.Rules), plural(len(inv.Rules)))
	}
	for _, rule := range inv.Rules {
		fmt.Fprintf(b, "  %s (%s) enabled=%t", rule.Name, rule.ID, rule.Enabled)
		switch {
		case rule.Type == 0 && rule.AP != nil:
			fmt.Fprintf(b, "  service VLAN: %s  client VLANs: %s", rule.AP.Service, rule.AP.Client)
		case rule.Type == 1 && rule.Gateway != nil:
			fmt.Fprintf(b, "  service network IDs: %s  client network IDs: %s", strings.Join(rule.Gateway.Service, ", "), strings.Join(rule.Gateway.Client, ", "))
		}
		fmt.Fprintf(b, "  Bonjour profile IDs: %s\n", strings.Join(rule.ProfileIDs, ", "))
	}
}
