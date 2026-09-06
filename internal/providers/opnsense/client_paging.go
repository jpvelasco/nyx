package opnsense

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	// maxListPages caps the number of page requests fetchPagedList issues.
	// A controller that reports a huge total (or ignores current) would
	// otherwise loop forever.
	maxListPages = 100
)

// listPageSize is the page size used for all paginated list endpoints.
// Keeps the walk to one or two round trips for realistic rule sets.
// Tests shrink it so a multi-page walk can be asserted without 500+ rows.
var listPageSize = 500

// pagedEnvelope is the paging wrapper OPNsense's searchRule/searchItem
// endpoints return.
type pagedEnvelope struct {
	Total    int             `json:"total"`
	RowCount int             `json:"rowCount"`
	Current  int             `json:"current"`
	Rows     json.RawMessage `json:"rows"`
}

// fetchPagedList walks a paged OPNsense list endpoint ({"total":N,
// "rowCount":P,"current":C,"rows":[...]}), sending current/rowCount
// (1-based) until every row is collected. Rows are collected as raw JSON so
// callers can decode each row leniently (the controller adds fields across
// versions and a single malformed row must not fail the whole read).
// Returns the total row count reported by the API on the first page.
func fetchPagedList(ctx context.Context, c *Client, path string, pageSize int, rowsDest *[]json.RawMessage) (int, error) {
	var (
		all   []json.RawMessage
		total int
	)
	for page := 1; ; page++ {
		if page > maxListPages {
			return 0, fmt.Errorf("%s: controller did not terminate after %d pages — it may be ignoring current", path, maxListPages)
		}
		query := url.Values{
			"current":  {strconv.Itoa(page)},
			"rowCount": {strconv.Itoa(pageSize)},
		}.Encode()

		var env pagedEnvelope
		if err := getJSON(ctx, c, path+"?"+query, &env); err != nil {
			return 0, err
		}
		if page == 1 {
			total = env.Total
		}

		var pageRows []json.RawMessage
		if len(env.Rows) > 0 {
			if err := json.Unmarshal(env.Rows, &pageRows); err != nil {
				return 0, fmt.Errorf("decoding paged list response: %w", err)
			}
		}
		all = append(all, pageRows...)

		if len(pageRows) < pageSize {
			break
		}
		if env.Total > 0 && len(all) >= env.Total {
			break
		}
		if env.RowCount > 0 && len(pageRows) < env.RowCount {
			break
		}
	}
	*rowsDest = all
	return total, nil
}

// remapPagedDecode keeps the historical decode-error prefix when the
// paging envelope itself is malformed. Transport and HTTP errors pass
// through unchanged so 403 privilege degradation still matches.
func remapPagedDecode(err error, prefix string) error {
	if err != nil && strings.Contains(err.Error(), "decoding paged list response") {
		return fmt.Errorf("%s: %w", prefix, err)
	}
	return err
}

// getJSON performs an authenticated GET and decodes the JSON body into dest.
func getJSON(ctx context.Context, c *Client, path string, dest interface{}) error {
	resp, err := c.do(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(dest); err != nil {
		return fmt.Errorf("decoding paged list response: %w", err)
	}
	return nil
}
