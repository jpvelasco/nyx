package service

import (
	"context"
	"errors"
	"slices"

	backend "github.com/jpvelasco/nyx/internal/backends/omada"
)

type OmadaACLOrderRequest struct {
	Scope             string
	Expected, Desired []string
}
type OmadaACLOrderResult struct {
	Site    string                `json:"site"`
	Scope   string                `json:"scope"`
	Outcome string                `json:"outcome"`
	DryRun  bool                  `json:"dry_run"`
	Before  []backend.ACLPosition `json:"before"`
	After   []backend.ACLPosition `json:"after"`
}

// ACLOrder accepts a complete permutation of the current scope. Real changes
// require the order seen during preview so a stale plan cannot change another rule.
func (s *OmadaService) ACLOrder(ctx context.Context, opts OmadaOptions, req OmadaACLOrderRequest, dryRun bool) (*OmadaACLOrderResult, error) {
	scope, ok := backend.ScopeFromLabel(req.Scope)
	if req.Scope == "eap" {
		scope, ok = backend.ACLTypeEAP, true
	}
	if !ok || req.Scope == "" {
		return nil, errors.New("select the gateway, switch or eap ACL scope")
	}
	if !dryRun && (opts.Site == "" || len(req.Expected) == 0 || len(req.Desired) == 0) {
		return nil, errors.New("apply requires the site, expected order and desired order from a preview")
	}
	client, site, err := s.session(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer client.Logout(ctx) //nolint:errcheck
	before, err := client.ACLOrder(ctx, site.EffectiveID(), scope)
	if err != nil {
		return nil, err
	}
	res := &OmadaACLOrderResult{Site: site.Name, Scope: scope.Scope(), Before: before, After: slices.Clone(before), Outcome: "unchanged", DryRun: dryRun}
	if len(req.Desired) == 0 {
		return res, nil
	}
	if len(req.Desired) != len(before) {
		return nil, errors.New("desired order must include every rule in the scope exactly once")
	}
	ids := make([]string, len(before))
	seen := make(map[string]bool, len(before))
	for i, rule := range before {
		ids[i] = rule.ID
		seen[rule.ID] = true
	}
	for i, id := range req.Desired {
		if !seen[id] {
			return nil, errors.New("desired order contains a missing or repeated rule")
		}
		delete(seen, id)
		res.After[i].ID = id
	}
	if slices.Equal(req.Desired, ids) {
		return res, nil
	}
	if len(req.Expected) > 0 && !slices.Equal(req.Expected, ids) {
		return nil, errors.New("current ACL order changed; request a new preview")
	}
	res.Outcome = "reorder"
	if dryRun {
		return res, nil
	}
	writeErr := client.SetACLOrder(ctx, site.EffectiveID(), scope, res.After)
	observed, readErr := client.ACLOrder(ctx, site.EffectiveID(), scope)
	if readErr != nil {
		return nil, errors.Join(errors.New("could not verify ACL order; re-read before retrying"), writeErr, readErr)
	}
	if !slices.Equal(observed, res.After) {
		return nil, errors.Join(errors.New("readback did not confirm the desired ACL order"), writeErr)
	}
	res.Outcome = "reordered"
	res.After = observed
	return res, nil
}
