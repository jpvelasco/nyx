package service

import (
	"context"
	"fmt"

	opnsensebackend "github.com/jpvelasco/nyx/internal/providers/opnsense"
)

// OpnsenseUnboundSettings is the observe subset of Unbound DNS.
type OpnsenseUnboundSettings struct {
	Enabled    bool                          `json:"enabled"`
	Running    bool                          `json:"running"`
	Interfaces []string                      `json:"interfaces,omitempty"`
	Hosts      []OpnsenseUnboundHostOverride `json:"hosts,omitempty"`
}

// OpnsenseUnboundHostOverride is one Unbound host override.
type OpnsenseUnboundHostOverride struct {
	UUID        string `json:"uuid,omitempty"`
	Hostname    string `json:"hostname,omitempty"`
	Domain      string `json:"domain,omitempty"`
	IP          string `json:"ip,omitempty"`
	Description string `json:"description,omitempty"`
}

// GetUnboundSettings returns Unbound enable/interfaces/hosts (settings/get).
func (s *OpnsenseService) GetUnboundSettings(ctx context.Context, opts OpnsenseOptions) (*OpnsenseUnboundSettings, error) {
	got, err := s.client(opts).GetUnboundSettings(ctx)
	if err != nil {
		return nil, err
	}
	return flattenUnbound(got), nil
}

// ListUnboundOverrides returns Unbound host overrides.
func (s *OpnsenseService) ListUnboundOverrides(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseUnboundHostOverride, error) {
	got, err := s.client(opts).GetUnboundHostOverrides(ctx)
	if err != nil {
		return nil, err
	}
	return flattenUnboundHosts(got), nil
}

// GetUnboundStatus returns whether Unbound reports as running.
func (s *OpnsenseService) GetUnboundStatus(ctx context.Context, opts OpnsenseOptions) (bool, error) {
	return s.client(opts).GetUnboundServiceStatus(ctx)
}

func flattenUnbound(in *opnsensebackend.UnboundSettings) *OpnsenseUnboundSettings {
	if in == nil {
		return nil
	}
	return &OpnsenseUnboundSettings{
		Enabled:    in.Enabled,
		Running:    in.Running,
		Interfaces: in.Interfaces,
		Hosts:      flattenUnboundHosts(in.Hosts),
	}
}

func flattenUnboundHosts(in []opnsensebackend.UnboundHostOverride) []OpnsenseUnboundHostOverride {
	if len(in) == 0 {
		return nil
	}
	out := make([]OpnsenseUnboundHostOverride, len(in))
	for i, h := range in {
		out[i] = OpnsenseUnboundHostOverride{UUID: h.UUID, Hostname: h.Hostname, Domain: h.Domain, IP: h.IP, Description: h.Description}
	}
	return out
}

// OpnsenseUnboundOverrideRequest is a plan/apply Unbound host-override mutation.
type OpnsenseUnboundOverrideRequest struct {
	Hostname    string
	Domain      string
	IP          string
	UUID        string
	Description string
	Delete      bool
}

// OpnsenseUnboundOverridePlan previews a host-override mutation.
type OpnsenseUnboundOverridePlan struct {
	Action   string `json:"action"`
	UUID     string `json:"uuid,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Domain   string `json:"domain,omitempty"`
	IP       string `json:"ip,omitempty"`

	// effective is the resolved update payload: requested fields overlay
	// the existing record so a partial UUID update preserves hostname and
	// domain instead of clearing them. Plan and apply share it, so the
	// dry-run surfaces exactly what a real apply would send.
	effective *opnsensebackend.UnboundHostWrite
}

// OpnsenseUnboundOverrideApplyResult is the apply outcome.
type OpnsenseUnboundOverrideApplyResult struct {
	Outcome  string `json:"outcome"`
	UUID     string `json:"uuid,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Domain   string `json:"domain,omitempty"`
	IP       string `json:"ip,omitempty"`
	DryRun   bool   `json:"dry_run"`
}

// PlanUnboundOverride previews creating, updating, or deleting a host override.
// Matching hostname+domain+ip is unchanged; missing creates; different IP updates;
// delete of a missing override is unchanged.
func (s *OpnsenseService) PlanUnboundOverride(ctx context.Context, opts OpnsenseOptions, req OpnsenseUnboundOverrideRequest) (*OpnsenseUnboundOverridePlan, error) {
	if !req.Delete && (req.Hostname == "" || req.IP == "") && req.UUID == "" {
		return nil, fmt.Errorf("hostname and ip are required (or uuid for delete)")
	}
	if req.Delete && req.UUID == "" && req.Hostname == "" {
		return nil, fmt.Errorf("uuid or hostname is required for delete")
	}
	rows, err := s.client(opts).GetUnboundHostOverrides(ctx)
	if err != nil {
		return nil, err
	}
	plan := &OpnsenseUnboundOverridePlan{UUID: req.UUID, Hostname: req.Hostname, Domain: req.Domain, IP: req.IP}
	cur, ok := opnsensebackend.FindUnboundOverride(rows, req.UUID, req.Hostname, req.Domain)
	if req.Delete {
		if !ok {
			plan.Action = "unchanged"
			return plan, nil
		}
		plan.Action = "delete"
		plan.UUID = cur.UUID
		plan.Hostname = cur.Hostname
		plan.Domain = cur.Domain
		plan.IP = cur.IP
		return plan, nil
	}
	if !ok {
		plan.Action = "create"
		plan.effective = &opnsensebackend.UnboundHostWrite{Hostname: req.Hostname, Domain: req.Domain, IP: req.IP, Description: req.Description}
		return plan, nil
	}
	// Resolve one effective update payload from the existing record and the
	// requested fields: omitted fields preserve the existing hostname,
	// domain, IP, and description, so a partial UUID update cannot clear
	// the record's identity. Plan and apply share this payload.
	plan.UUID = cur.UUID
	eff := &opnsensebackend.UnboundHostWrite{
		Hostname:    firstNonEmptySvc(req.Hostname, cur.Hostname),
		Domain:      firstNonEmptySvc(req.Domain, cur.Domain),
		IP:          firstNonEmptySvc(req.IP, cur.IP),
		Description: firstNonEmptySvc(req.Description, cur.Description),
	}
	plan.effective = eff
	// The plan surfaces the effective identity — the dry-run shows exactly
	// what a real apply would send.
	plan.Hostname = eff.Hostname
	plan.Domain = eff.Domain
	plan.IP = eff.IP
	if opnsensebackend.UnboundOverrideMatches(cur, eff.Hostname, eff.Domain, eff.IP) {
		plan.Action = "unchanged"
		return plan, nil
	}
	plan.Action = "update"
	return plan, nil
}

// ApplyUnboundOverride creates/updates/deletes a host override. Dry-run
// issues zero POSTs. A real apply reconfigures Unbound.
func (s *OpnsenseService) ApplyUnboundOverride(ctx context.Context, opts OpnsenseOptions, req OpnsenseUnboundOverrideRequest, dryRun bool) (*OpnsenseUnboundOverrideApplyResult, error) {
	plan, err := s.PlanUnboundOverride(ctx, opts, req)
	if err != nil {
		return nil, err
	}
	res := &OpnsenseUnboundOverrideApplyResult{
		Outcome:  plan.Action,
		UUID:     plan.UUID,
		Hostname: plan.Hostname,
		Domain:   plan.Domain,
		IP:       plan.IP,
		DryRun:   dryRun,
	}
	if dryRun || plan.Action == "unchanged" {
		return res, nil
	}
	client := s.client(opts)
	switch plan.Action {
	case "create":
		// The effective payload resolved during planning drives the write:
		// omitted fields preserve the existing record's identity instead
		// of sending empty strings (#182). Deletes carry no payload.
		id, err := client.CreateUnboundOverride(ctx, *plan.effective)
		if err != nil {
			return nil, err
		}
		res.UUID = id
		res.Outcome = "created"
	case "update":
		if err := client.SetUnboundOverride(ctx, plan.UUID, *plan.effective); err != nil {
			return nil, err
		}
		res.Outcome = "updated"
	case "delete":
		if err := client.DeleteUnboundOverride(ctx, plan.UUID); err != nil {
			return nil, err
		}
		res.Outcome = "deleted"
	}
	if err := client.ReconfigureUnbound(ctx); err != nil {
		return nil, err
	}
	return res, nil
}
