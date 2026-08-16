package omada

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
)

// defaultPageSize is the page size used for all paginated list endpoints.
const defaultPageSize = 200

// maxPages caps the number of page requests fetchPaged will issue. A
// controller that reports totalRows: 0 (or omits it) and ignores currentPage
// would otherwise loop forever.
const maxPages = 100

// fetchPaged walks a paged Omada list endpoint ({"totalRows":N,"data":[...]}),
// following currentPage until every row is collected. Controllers that don't
// paginate can still return a direct array payload — that shape is accepted
// and returned in full. Returns the collected items and the total row count
// reported by the API on the first page.
func fetchPaged[T any](ctx context.Context, c *Client, basePath string, pageSize int, extraQuery ...string) ([]T, int, error) {
	items, total, _, err := fetchPagedMeta[T, struct{}](ctx, c, basePath, pageSize, extraQuery...)
	return items, total, err
}

// fetchPagedMeta is fetchPaged plus a first-page decode into M so callers
// can read sibling fields (e.g. aclDisable) without a second request.
func fetchPagedMeta[T any, M any](ctx context.Context, c *Client, basePath string, pageSize int, extraQuery ...string) ([]T, int, M, error) {
	var (
		items     []T
		total     int
		firstData []T
		meta      M
	)
	for page := 1; ; page++ {
		if page > maxPages {
			return nil, 0, meta, fmt.Errorf("%s: controller did not terminate after %d pages — it may be ignoring currentPage", basePath, maxPages)
		}
		query := "currentPage=" + strconv.Itoa(page) + "&currentPageSize=" + strconv.Itoa(pageSize)
		if len(extraQuery) > 0 {
			query += "&" + strings.Join(extraQuery, "&")
		}
		var raw json.RawMessage
		if err := c.get(ctx, basePath+"?"+query, &raw); err != nil {
			return nil, 0, meta, err
		}

		var paged struct {
			TotalRows int `json:"totalRows"`
			Data      []T `json:"data"`
		}
		if err := json.Unmarshal(raw, &paged); err != nil {
			var direct []T
			if derr := json.Unmarshal(raw, &direct); derr == nil {
				return direct, len(direct), meta, nil
			}
			return nil, 0, meta, fmt.Errorf("decoding paged list response: %w", err)
		}
		if page == 1 {
			total = paged.TotalRows
			firstData = paged.Data
			_ = json.Unmarshal(raw, &meta)
		} else if len(paged.Data) > 0 && reflect.DeepEqual(paged.Data, firstData) {
			return nil, 0, meta, fmt.Errorf("%s: controller repeated page 1 at page %d — it is ignoring currentPage", basePath, page)
		}
		items = append(items, paged.Data...)
		if len(paged.Data) == 0 || (total > 0 && len(items) >= total) {
			break
		}
	}
	return items, total, meta, nil
}
