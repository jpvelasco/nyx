package omada

import (
	"context"
	"errors"
	"fmt"
	"sort"
)

// ACLPosition is the order of one rule in a single enforcement scope.
type ACLPosition struct {
	ID    string `json:"id"`
	Index int    `json:"index"`
}

type aclOrderRow struct {
	ID    string `json:"id"`
	Index *int   `json:"index"`
}

// ACLOrder reads just the identity and priority fields common to all three scopes.
func (c *Client) ACLOrder(ctx context.Context, site string, scope ACLType) ([]ACLPosition, error) {
	rows, total, err := fetchPaged[aclOrderRow](ctx, c, aclScopePath(site, scope), defaultPageSize)
	if err != nil {
		return nil, err
	}
	if total != len(rows) {
		return nil, errors.New("incomplete ACL order inventory")
	}
	order := make([]ACLPosition, 0, len(rows))
	ids := map[string]bool{}
	indexes := map[int]bool{}
	for _, row := range rows {
		if row.ID == "" || row.Index == nil || *row.Index < 0 || ids[row.ID] || indexes[*row.Index] {
			return nil, errors.New("missing or ambiguous rule identity or index in ACL inventory")
		}
		ids[row.ID] = true
		indexes[*row.Index] = true
		order = append(order, ACLPosition{ID: row.ID, Index: *row.Index})
	}
	sort.Slice(order, func(i, j int) bool { return order[i].Index < order[j].Index })
	return order, nil
}

// SetACLOrder submits the complete site and scope permutation once. The caller
// must read ACLOrder after the request, including when the response is lost.
func (c *Client) SetACLOrder(ctx context.Context, site string, scope ACLType, positions []ACLPosition) error {
	indexes := make(map[string]int, len(positions))
	for _, p := range positions {
		indexes[p.ID] = p.Index
	}
	return c.postCreate(ctx, fmt.Sprintf("sites/%s/acls/modifyIndex", site), map[string]any{"type": scope.Scope(), "indexes": indexes}, nil)
}
