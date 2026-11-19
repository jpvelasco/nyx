package opnsense

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
)

const aliasTableAPI = "/firewall/alias_util/"

var aliasTableName = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_.-]*$`)

// BlocklistChange records a preview or an acknowledged table update.
type BlocklistChange struct {
	Action  string `json:"action"`
	Table   string `json:"table"`
	Address string `json:"address,omitempty"`
	Status  string `json:"status"`
}

// ListBlocklistTables lists the firewall's runtime pf tables.
func (c *Client) ListBlocklistTables(ctx context.Context) ([]string, error) {
	tables := []string{}
	err := getJSON(ctx, c, aliasTableAPI+"aliases", &tables)
	return tables, err
}

// ListBlocklist returns all matching rows for one pf table.
func (c *Client) ListBlocklist(ctx context.Context, table, search string) ([]json.RawMessage, error) {
	if !aliasTableName.MatchString(table) {
		return nil, fmt.Errorf("invalid pf table name")
	}
	rows := []json.RawMessage{}
	_, err := fetchPagedListPOSTSearch(ctx, c, aliasTableAPI+"list/"+table, listPageSize, search, &rows)
	if rows == nil {
		rows = []json.RawMessage{}
	}
	return rows, err
}

// BlocklistReferences returns OPNsense's rule and alias references for one IP.
func (c *Client) BlocklistReferences(ctx context.Context, address string) (json.RawMessage, error) {
	ip, err := netip.ParseAddr(address)
	if err != nil || ip.Zone() != "" {
		return nil, fmt.Errorf("references requires an IPv4 or IPv6 address")
	}
	var result json.RawMessage
	err = c.blocklistPOST(ctx, aliasTableAPI+"find_references", map[string]string{"ip": ip.String()}, &result)
	return result, err
}

// UpdateBlocklist previews or executes one explicitly authorized pf update.
func (c *Client) UpdateBlocklist(ctx context.Context, action, table, address string, confirmed bool) (BlocklistChange, error) {
	result := BlocklistChange{Action: action, Table: table, Address: address, Status: "dry_run"}
	if !aliasTableName.MatchString(table) {
		return result, fmt.Errorf("invalid pf table name")
	}
	var operation string
	var body map[string]string
	switch action {
	case "unblock":
		ip, ipErr := netip.ParseAddr(address)
		_, prefixErr := netip.ParsePrefix(address)
		if (ipErr != nil || ip.Zone() != "") && prefixErr != nil {
			return result, fmt.Errorf("unblock requires an IP address or CIDR prefix")
		}
		operation = "delete"
		body = map[string]string{"address": address}
	case "flush":
		operation = "flush"
	default:
		return result, fmt.Errorf("invalid blocklist action")
	}
	if !confirmed {
		return result, nil
	}
	var response struct {
		Status string `json:"status"`
	}
	if err := c.blocklistPOST(ctx, aliasTableAPI+operation+"/"+table, body, &response); err != nil {
		return result, err
	}
	if response.Status != "done" {
		return result, fmt.Errorf("firewall did not acknowledge the blocklist update")
	}
	result.Status = "acknowledged"
	return result, nil
}

func (c *Client) blocklistPOST(ctx context.Context, path string, fields map[string]string, dest any) error {
	body, err := json.Marshal(fields)
	if err != nil {
		return err
	}
	resp, err := c.do(ctx, http.MethodPost, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(dest)
}
