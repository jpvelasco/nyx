package omada

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// defaultPageSize is the page size used for all paginated list endpoints.
const defaultPageSize = 200

// fetchPaged walks a paged Omada list endpoint ({"totalRows":N,"data":[...]}),
// following currentPage until every row is collected. Controllers that don't
// paginate can still return a direct array payload — that shape is accepted
// and returned in full. Returns the collected items and the total row count
// reported by the API on the first page.
func fetchPaged[T any](ctx context.Context, c *Client, basePath string, pageSize int, extraQuery ...string) ([]T, int, error) {
	var (
		items []T
		total int
	)
	for page := 1; ; page++ {
		query := "currentPage=" + strconv.Itoa(page) + "&currentPageSize=" + strconv.Itoa(pageSize)
		if len(extraQuery) > 0 {
			query += "&" + strings.Join(extraQuery, "&")
		}
		var raw json.RawMessage
		if err := c.get(ctx, basePath+"?"+query, &raw); err != nil {
			return nil, 0, err
		}

		var paged struct {
			TotalRows int `json:"totalRows"`
			Data      []T `json:"data"`
		}
		if err := json.Unmarshal(raw, &paged); err != nil {
			var direct []T
			if derr := json.Unmarshal(raw, &direct); derr == nil {
				return direct, len(direct), nil
			}
			return nil, 0, fmt.Errorf("decoding paged list response: %w", err)
		}
		if page == 1 {
			total = paged.TotalRows
		}
		items = append(items, paged.Data...)
		if len(paged.Data) == 0 || (total > 0 && len(items) >= total) {
			break
		}
	}
	return items, total, nil
}
