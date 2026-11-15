package service

import (
	"context"
	"fmt"
	"strings"

	opnsensebackend "github.com/jpvelasco/nyx/internal/providers/opnsense"
)

// OpnsenseVLANRequest is a plan/apply VLAN or bridge-member mutation.
type OpnsenseVLANRequest struct {
	Kind        string // vlan (default) | bridge
	Parent      string
	Tag         int
	Description string
	UUID        string
	Members     []string
	Delete      bool
}

// OpnsenseVLANPlan previews a VLAN/bridge mutation.
type OpnsenseVLANPlan struct {
	Action   string   `json:"action"`
	Kind     string   `json:"kind"`
	UUID     string   `json:"uuid,omitempty"`
	Warning  string   `json:"warning"`
	Warnings []string `json:"warnings,omitempty"`
}

// OpnsenseVLANApplyResult is the apply outcome.
type OpnsenseVLANApplyResult struct {
	Outcome  string   `json:"outcome"`
	Kind     string   `json:"kind"`
	UUID     string   `json:"uuid,omitempty"`
	DryRun   bool     `json:"dry_run"`
	Warning  string   `json:"warning"`
	Warnings []string `json:"warnings,omitempty"`
}

func vlanKind(kind string) string {
	if strings.EqualFold(kind, "bridge") {
		return "bridge"
	}
	return "vlan"
}

// OpnsenseVLAN is a configured VLAN device.
type OpnsenseVLAN struct {
	UUID        string `json:"uuid"`
	Parent      string `json:"parent"`
	Tag         int    `json:"tag"`
	Description string `json:"description,omitempty"`
	Device      string `json:"device,omitempty"`
}

// ListVLANs returns configured VLAN devices.
func (s *OpnsenseService) ListVLANs(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseVLAN, error) {
	rows, err := s.client(opts).GetVLANs(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]OpnsenseVLAN, 0, len(rows))
	for _, v := range rows {
		out = append(out, OpnsenseVLAN{UUID: v.UUID, Parent: v.Parent, Tag: v.Tag, Description: v.Description, Device: v.Device})
	}
	return out, nil
}

// PlanVLAN previews creating, updating, or deleting a VLAN device, or
// updating a bridge's members. The assign/IP gap is always stated.
func (s *OpnsenseService) PlanVLAN(ctx context.Context, opts OpnsenseOptions, req OpnsenseVLANRequest) (*OpnsenseVLANPlan, error) {
	kind := vlanKind(req.Kind)
	plan := &OpnsenseVLANPlan{Kind: kind, UUID: req.UUID, Warning: opnsensebackend.AssignIPGapWarning, Warnings: []string{opnsensebackend.AssignIPGapWarning}}
	client := s.client(opts)
	if kind == "bridge" {
		if req.UUID == "" && !req.Delete {
			return nil, fmt.Errorf("uuid is required for bridge member updates")
		}
		bridges, err := client.GetBridgeSettings(ctx)
		if err != nil {
			return nil, err
		}
		var cur *opnsensebackend.Bridge
		for i := range bridges {
			if strings.EqualFold(bridges[i].UUID, req.UUID) {
				cur = &bridges[i]
				break
			}
		}
		if req.Delete {
			return nil, fmt.Errorf("bridge delete is not supported; update members instead")
		}
		if cur == nil {
			return nil, fmt.Errorf("bridge %s not found", req.UUID)
		}
		if opnsensebackend.BridgeMembersMatch(cur.Members, req.Members) {
			plan.Action = "unchanged"
			return plan, nil
		}
		plan.Action = "update"
		return plan, nil
	}
	identifiedByUUID := req.Delete && req.UUID != ""
	if !identifiedByUUID && (req.Parent == "" || req.Tag <= 0) {
		return nil, fmt.Errorf("parent and tag are required (or uuid for delete)")
	}
	vlans, err := client.GetVLANs(ctx)
	if err != nil {
		return nil, err
	}
	cur, ok := opnsensebackend.FindVLAN(vlans, req.UUID, req.Parent, req.Tag)
	if req.Delete {
		if !ok {
			plan.Action = "unchanged"
			return plan, nil
		}
		plan.Action = "delete"
		plan.UUID = cur.UUID
		return plan, nil
	}
	w := opnsensebackend.VLANWrite{Parent: req.Parent, Tag: req.Tag, Description: req.Description}
	if !ok {
		plan.Action = "create"
		return plan, nil
	}
	plan.UUID = cur.UUID
	if opnsensebackend.VLANMatchesWrite(cur, w) {
		plan.Action = "unchanged"
		return plan, nil
	}
	plan.Action = "update"
	return plan, nil
}

// ApplyVLAN creates/updates/deletes a VLAN device or updates bridge members.
// Dry-run by default at the MCP layer. A real apply reconfigures.
func (s *OpnsenseService) ApplyVLAN(ctx context.Context, opts OpnsenseOptions, req OpnsenseVLANRequest, dryRun bool) (*OpnsenseVLANApplyResult, error) {
	plan, err := s.PlanVLAN(ctx, opts, req)
	if err != nil {
		return nil, err
	}
	res := &OpnsenseVLANApplyResult{
		Outcome:  plan.Action,
		Kind:     plan.Kind,
		UUID:     plan.UUID,
		DryRun:   dryRun,
		Warning:  plan.Warning,
		Warnings: plan.Warnings,
	}
	if dryRun || plan.Action == "unchanged" {
		return res, nil
	}
	client := s.client(opts)
	if plan.Kind == "bridge" {
		if err := client.SetBridgeMembers(ctx, req.UUID, req.Members, req.Description); err != nil {
			return nil, err
		}
		if err := client.ReconfigureBridges(ctx); err != nil {
			return nil, err
		}
		res.Outcome = "updated"
		return res, nil
	}
	w := opnsensebackend.VLANWrite{Parent: req.Parent, Tag: req.Tag, Description: req.Description}
	switch plan.Action {
	case "create":
		id, err := client.CreateVLAN(ctx, w)
		if err != nil {
			return nil, err
		}
		res.UUID = id
		res.Outcome = "created"
	case "update":
		if err := client.SetVLAN(ctx, plan.UUID, w); err != nil {
			return nil, err
		}
		res.Outcome = "updated"
	case "delete":
		if err := client.DeleteVLAN(ctx, plan.UUID); err != nil {
			return nil, err
		}
		res.Outcome = "deleted"
	}
	if err := client.ReconfigureVLANs(ctx); err != nil {
		return nil, err
	}
	return res, nil
}
