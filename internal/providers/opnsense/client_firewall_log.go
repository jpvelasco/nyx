package opnsense

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jpvelasco/nyx/internal/textsafe"
)

const (
	firewallLogPath   = "/diagnostics/firewall/log"
	firewallStatsPath = "/diagnostics/firewall/stats"
)

// FirewallLogQuery filters a single newest-first page of controller logs.
type FirewallLogQuery struct {
	Limit                                                            int
	Before, Source, Destination, Action, Direction, Interface, Since string
}

// FirewallLogPage preserves the cursor from the unfiltered page.
type FirewallLogPage struct {
	Rows       []FirewallLogEntry `json:"rows"`
	NextBefore string             `json:"next_before,omitempty"`
}

// FirewallLogEntry contains the fields needed to inspect a logged packet.
type FirewallLogEntry struct {
	Source          string `json:"src"`
	Destination     string `json:"dst"`
	SourcePort      string `json:"srcport,omitempty"`
	DestinationPort string `json:"dstport,omitempty"`
	Action          string `json:"action"`
	Direction       string `json:"dir"`
	Interface       string `json:"interface"`
	Label           string `json:"label,omitempty"`
	Timestamp       string `json:"__timestamp__"`
	Digest          string `json:"__digest__"`
}

// GetFirewallLog reads a bounded page and applies filters locally.
func (c *Client) GetFirewallLog(ctx context.Context, query FirewallLogQuery) (FirewallLogPage, error) {
	if query.Limit == 0 {
		query.Limit = 1000
	}
	if query.Limit < 1 || query.Limit > 1000 {
		return FirewallLogPage{}, fmt.Errorf("limit must be between 1 and 1000")
	}
	if query.Before != "" && !validLogDigest(query.Before) {
		return FirewallLogPage{}, fmt.Errorf("before must be a 32-character hexadecimal digest")
	}
	var since time.Time
	if query.Since != "" {
		var err error
		since, err = time.Parse(time.RFC3339, query.Since)
		if err != nil {
			return FirewallLogPage{}, fmt.Errorf("since must be an RFC3339 timestamp")
		}
	}
	fetchLimit := query.Limit
	// OPNsense stops at digest inclusively, so backward paging uses a bounded
	// local search instead of sending the digest as the controller's stop point.
	if query.Before != "" {
		fetchLimit = 5000
	}
	rows, err := readFirewallJSON[FirewallLogEntry](ctx, c, firewallLogPath, url.Values{"limit": {strconv.Itoa(fetchLimit)}})
	if err != nil {
		return FirewallLogPage{}, err
	}
	if query.Before != "" {
		index := slices.IndexFunc(rows, func(row FirewallLogEntry) bool { return strings.EqualFold(row.Digest, query.Before) })
		if index < 0 {
			return FirewallLogPage{}, fmt.Errorf("before digest is outside the newest 5000 firewall log records")
		}
		rows = rows[index+1:]
	}
	rows = rows[:min(len(rows), query.Limit)]
	return filterFirewallLog(rows, query, since)
}

// FirewallLogStat represents one of the controller's top groups or its other bucket.
type FirewallLogStat struct {
	Label string `json:"label"`
	Value int    `json:"value"`
}

// GetFirewallLogStats counts up to limit of the newest rows by a controller record field.
func (c *Client) GetFirewallLogStats(ctx context.Context, limit int, groupBy string) ([]FirewallLogStat, error) {
	if limit == 0 {
		limit = 5000
	}
	if limit < 1 || limit > 5000 {
		return nil, fmt.Errorf("limit must be between 1 and 5000")
	}
	if groupBy == "" {
		groupBy = "interface"
	}
	rows, err := readFirewallJSON[struct {
		Label json.RawMessage `json:"label"`
		Value int             `json:"value"`
	}](ctx, c, firewallStatsPath, url.Values{"limit": {strconv.Itoa(limit)}, "group_by": {groupBy}})
	if err != nil {
		return nil, err
	}
	stats := make([]FirewallLogStat, 0, len(rows))
	for _, row := range rows {
		var label any
		if err := json.Unmarshal(row.Label, &label); err != nil {
			return nil, fmt.Errorf("invalid firewall statistic label")
		}
		switch label := label.(type) {
		case string:
			stats = append(stats, FirewallLogStat{Label: textsafe.Printable(label), Value: row.Value})
		case float64:
			stats = append(stats, FirewallLogStat{Label: string(row.Label), Value: row.Value})
		default:
			return nil, fmt.Errorf("invalid firewall statistic label")
		}
	}
	return stats, nil
}

func readFirewallJSON[T any](ctx context.Context, c *Client, path string, params url.Values) ([]T, error) {
	resp, err := c.do(ctx, http.MethodGet, path+"?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	const maxResponseBytes = 8 << 20
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("reading firewall diagnostics: %w", err)
	}
	if len(raw) > maxResponseBytes {
		return nil, fmt.Errorf("firewall diagnostics response exceeds 8 MiB")
	}
	var rows []T
	if err := json.Unmarshal(raw, &rows); err != nil || rows == nil {
		return nil, fmt.Errorf("invalid firewall diagnostics response: expected an array of entries")
	}
	return rows, nil
}

func validLogDigest(value string) bool {
	if len(value) != 32 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func filterFirewallLog(rows []FirewallLogEntry, query FirewallLogQuery, since time.Time) (FirewallLogPage, error) {
	page := FirewallLogPage{Rows: make([]FirewallLogEntry, 0, len(rows))}
	if len(rows) != 0 {
		page.NextBefore = rows[len(rows)-1].Digest
		if !validLogDigest(page.NextBefore) {
			return FirewallLogPage{}, fmt.Errorf("firewall log page has an invalid final digest")
		}
		if strings.EqualFold(page.NextBefore, query.Before) {
			return FirewallLogPage{}, fmt.Errorf("firewall log cursor did not advance")
		}
	}
	now := time.Now()
	for _, row := range rows {
		if !logAddressMatches(row.Source, query.Source) || !logAddressMatches(row.Destination, query.Destination) ||
			!logFieldMatches(row.Action, query.Action) || !logFieldMatches(row.Direction, query.Direction) ||
			!logFieldMatches(row.Interface, query.Interface) {
			continue
		}
		if !since.IsZero() {
			timestamp, err := parseFirewallLogTimestamp(row.Timestamp, since.Location(), now)
			if err != nil {
				return FirewallLogPage{}, fmt.Errorf("cannot apply since filter: unrecognized firewall log timestamp")
			}
			if timestamp.Before(since) {
				continue
			}
		}
		for _, field := range []*string{&row.Source, &row.Destination, &row.SourcePort, &row.DestinationPort, &row.Action, &row.Direction, &row.Interface, &row.Label, &row.Timestamp, &row.Digest} {
			*field = textsafe.Printable(*field)
		}
		page.Rows = append(page.Rows, row)
	}
	return page, nil
}

// OPNsense strips positive offsets from RFC5424 timestamps and preserves
// RFC3164 wall times without years. Use the cutoff offset for wall times and
// the most recent year in which the RFC3164 timestamp could have occurred.
func parseFirewallLogTimestamp(value string, location *time.Location, now time.Time) (time.Time, error) {
	if timestamp, err := time.Parse(time.RFC3339, value); err == nil {
		return timestamp, nil
	}
	if timestamp, err := time.ParseInLocation("2006-01-02T15:04:05", value, location); err == nil {
		return timestamp, nil
	}
	year := now.In(location).Year()
	timestamp, err := time.ParseInLocation("2006 Jan 2 15:04:05", fmt.Sprintf("%d %s", year, value), location)
	if err == nil && timestamp.After(now) {
		return time.ParseInLocation("2006 Jan 2 15:04:05", fmt.Sprintf("%d %s", year-1, value), location)
	}
	return timestamp, err
}

func logFieldMatches(value, filter string) bool {
	return filter == "" || strings.EqualFold(value, filter)
}

func logAddressMatches(value, filter string) bool {
	if logFieldMatches(value, filter) {
		return true
	}
	address, _, _ := strings.Cut(value, "/")
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return false
	}
	if prefix, err := netip.ParsePrefix(filter); err == nil {
		return prefix.Contains(ip)
	}
	target, err := netip.ParseAddr(filter)
	return err == nil && target == ip
}
