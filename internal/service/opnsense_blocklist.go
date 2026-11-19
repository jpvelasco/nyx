package service

import (
	"context"
	"encoding/json"

	"github.com/jpvelasco/nyx/internal/providers/opnsense"
)

func (s *OpnsenseService) ListBlocklistTables(ctx context.Context, opts OpnsenseOptions) ([]string, error) {
	return s.client(opts).ListBlocklistTables(ctx)
}

func (s *OpnsenseService) ListBlocklist(ctx context.Context, opts OpnsenseOptions, table, search string) ([]json.RawMessage, error) {
	return s.client(opts).ListBlocklist(ctx, table, search)
}

func (s *OpnsenseService) BlocklistReferences(ctx context.Context, opts OpnsenseOptions, address string) (json.RawMessage, error) {
	return s.client(opts).BlocklistReferences(ctx, address)
}

func (s *OpnsenseService) UpdateBlocklist(ctx context.Context, opts OpnsenseOptions, action, table, address string, confirmed bool) (opnsense.BlocklistChange, error) {
	return s.client(opts).UpdateBlocklist(ctx, action, table, address, confirmed)
}
