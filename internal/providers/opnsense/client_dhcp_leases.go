package opnsense

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

const (
	dnsmasqSettingsPath = "/dnsmasq/settings/get"
	dnsmasqLeasesPath   = "/dnsmasq/leases/search"
	keaV4LeasesPath     = "/kea/leases4/search"
	keaV6LeasesPath     = "/kea/leases6/search"
)

var dhcpPrivileges = map[string]string{
	dnsmasqSettingsPath: "Services: Dnsmasq DNS/DHCP: Settings",
	dnsmasqLeasesPath:   "Services: Dnsmasq DNS/DHCP: Settings",
	keaV4LeasesPath:     "Services: DHCP: Kea(v4)",
	keaV6LeasesPath:     "Services: DHCP: Kea(v6)",
}

// GetDHCPLeases returns active DHCP leases from the configured provider.
func (c *Client) GetDHCPLeases(ctx context.Context) ([]DHCPLease, error) {
	settings, err := c.GetDnsmasqSettings(ctx)
	if err != nil {
		return nil, err
	}
	return c.getDHCPLeases(ctx, settings.Enabled)
}

func (c *Client) getDHCPLeases(ctx context.Context, dnsmasqEnabled bool) ([]DHCPLease, error) {
	paths := []string{keaV4LeasesPath, keaV6LeasesPath}
	if dnsmasqEnabled {
		paths = []string{dnsmasqLeasesPath}
	}
	var leases []DHCPLease
	for _, path := range paths {
		rows, err := c.fetchDHCPLeaseRows(ctx, path)
		if err != nil {
			return nil, err
		}
		leases = append(leases, rows...)
	}
	return leases, nil
}

func (c *Client) fetchDHCPLeaseRows(ctx context.Context, path string) ([]DHCPLease, error) {
	// The Bootgrid API uses rowCount=-1 to return the complete table.
	resp, err := c.do(ctx, http.MethodPost, path, []byte(`{"rowCount":-1,"sort":{"expire":"desc"}}`))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Leases []DHCPLease `json:"leases"`
		Rows   []struct {
			DHCPLease
			Address string `json:"address"`
			HWAddr  string `json:"hwaddr"`
			State   int    `json:"state"`
		} `json:"rows"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding DHCP leases response: %w", err)
	}
	if len(result.Leases) > 0 {
		return result.Leases, nil
	}
	leases := make([]DHCPLease, 0, len(result.Rows))
	for _, row := range result.Rows {
		// Kea marks inactive leases with nonzero state. Dnsmasq omits state.
		if row.State == 0 {
			lease := row.DHCPLease
			lease.IP = firstNonEmpty(row.Address, lease.IP)
			lease.MAC = firstNonEmpty(row.HWAddr, lease.MAC)
			leases = append(leases, lease)
		}
	}
	return leases, nil
}
