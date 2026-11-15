package service

import (
	"context"
	"fmt"
	"strings"

	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
)

// OmadaWLANGroup is a site WLAN group.
type OmadaWLANGroup struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name"`
}

// OmadaSSID is a site SSID in agent-friendly shape.
type OmadaSSID struct {
	ID          string `json:"id,omitempty"`
	Name        string `json:"name"`
	SSID        string `json:"ssid"`
	Enabled     bool   `json:"enabled"`
	WLANGroupID string `json:"wlan_group_id,omitempty"`
	VLANID      int    `json:"vlan_id,omitempty"`
	Security    string `json:"security,omitempty"`
	Band        string `json:"band,omitempty"`
}

// OmadaSSIDInventory is the observe payload: groups plus SSIDs.
type OmadaSSIDInventory struct {
	Groups []OmadaWLANGroup `json:"groups"`
	SSIDs  []OmadaSSID      `json:"ssids"`
}

// OmadaSSIDRequest is a plan/apply SSID mutation.
type OmadaSSIDRequest struct {
	Name      string
	SSID      string
	Enabled   bool
	WLANGroup string
	VLAN      int
	Security  string
	Band      string
	Delete    bool
}

// OmadaSSIDPlan previews an SSID create/update/delete.
type OmadaSSIDPlan struct {
	Action string `json:"action"`
	Name   string `json:"name"`
	ID     string `json:"id,omitempty"`
}

// OmadaSSIDApplyResult is the apply outcome.
type OmadaSSIDApplyResult struct {
	Outcome string `json:"outcome"`
	ID      string `json:"id,omitempty"`
	DryRun  bool   `json:"dry_run"`
}

func flattenOmadaSSID(s omadabackend.SSID) OmadaSSID {
	return OmadaSSID{
		ID:          s.ID,
		Name:        s.Name,
		SSID:        s.SSID,
		Enabled:     s.Enabled,
		WLANGroupID: s.WLANGroupID,
		VLANID:      s.VLANID,
		Security:    s.Security,
		Band:        s.Band,
	}
}

func (req OmadaSSIDRequest) write(wlanGroupID string) omadabackend.SSIDWrite {
	name := req.Name
	if name == "" {
		name = req.SSID
	}
	ssid := req.SSID
	if ssid == "" {
		ssid = req.Name
	}
	return omadabackend.SSIDWrite{
		Name:        name,
		SSID:        ssid,
		Enabled:     req.Enabled,
		WLANGroupID: wlanGroupID,
		VLANID:      req.VLAN,
		Security:    req.Security,
		Band:        req.Band,
	}
}

func resolveWLANGroupID(groups []omadabackend.WLANGroup, name string) string {
	if name == "" {
		return ""
	}
	for _, g := range groups {
		if strings.EqualFold(g.ID, name) || strings.EqualFold(g.Name, name) {
			return g.ID
		}
	}
	return name
}

// ListSSIDs returns site WLAN groups and SSIDs.
func (s *OmadaService) ListSSIDs(ctx context.Context, opts OmadaOptions) (*OmadaSSIDInventory, error) {
	return withSession(s, ctx, opts, func(client *omadabackend.Client, siteID string) (*OmadaSSIDInventory, error) {
		groups, err := client.GetWLANGroups(ctx, siteID)
		if err != nil {
			return nil, err
		}
		ssids, err := client.GetSSIDs(ctx, siteID)
		if err != nil {
			return nil, err
		}
		out := &OmadaSSIDInventory{
			Groups: make([]OmadaWLANGroup, 0, len(groups)),
			SSIDs:  make([]OmadaSSID, 0, len(ssids)),
		}
		for _, g := range groups {
			out.Groups = append(out.Groups, OmadaWLANGroup{ID: g.ID, Name: g.Name})
		}
		for _, row := range ssids {
			out.SSIDs = append(out.SSIDs, flattenOmadaSSID(row))
		}
		return out, nil
	})
}

// PlanSSID previews creating, updating, or deleting a site SSID.
func (s *OmadaService) PlanSSID(ctx context.Context, opts OmadaOptions, req OmadaSSIDRequest) (*OmadaSSIDPlan, error) {
	if req.Name == "" && req.SSID == "" {
		return nil, fmt.Errorf("name or ssid is required")
	}
	lookup := req.Name
	if lookup == "" {
		lookup = req.SSID
	}
	return withSession(s, ctx, opts, func(client *omadabackend.Client, siteID string) (*OmadaSSIDPlan, error) {
		ssids, err := client.GetSSIDs(ctx, siteID)
		if err != nil {
			return nil, err
		}
		cur, ok := omadabackend.FindSSID(ssids, lookup)
		plan := &OmadaSSIDPlan{Name: lookup}
		if req.Delete {
			if !ok {
				plan.Action = "unchanged"
				return plan, nil
			}
			plan.Action = "delete"
			plan.ID = cur.ID
			return plan, nil
		}
		groups, err := client.GetWLANGroups(ctx, siteID)
		if err != nil {
			return nil, err
		}
		w := req.write(resolveWLANGroupID(groups, req.WLANGroup))
		if !ok {
			plan.Action = "create"
			return plan, nil
		}
		plan.ID = cur.ID
		if omadabackend.SSIDMatchesWrite(cur, w) {
			plan.Action = "unchanged"
			return plan, nil
		}
		plan.Action = "update"
		return plan, nil
	})
}

// ApplySSID creates, updates, or deletes a site SSID. Dry-run by default
// at the MCP layer.
func (s *OmadaService) ApplySSID(ctx context.Context, opts OmadaOptions, req OmadaSSIDRequest, dryRun bool) (*OmadaSSIDApplyResult, error) {
	plan, err := s.PlanSSID(ctx, opts, req)
	if err != nil {
		return nil, err
	}
	res := &OmadaSSIDApplyResult{Outcome: plan.Action, ID: plan.ID, DryRun: dryRun}
	if dryRun || plan.Action == "unchanged" {
		return res, nil
	}
	return withSession(s, ctx, opts, func(client *omadabackend.Client, siteID string) (*OmadaSSIDApplyResult, error) {
		groups, err := client.GetWLANGroups(ctx, siteID)
		if err != nil {
			return nil, err
		}
		w := req.write(resolveWLANGroupID(groups, req.WLANGroup))
		switch plan.Action {
		case "create":
			id, err := client.CreateSSID(ctx, siteID, w)
			if err != nil {
				return nil, err
			}
			res.ID = id
			res.Outcome = "created"
		case "update":
			if err := client.UpdateSSID(ctx, siteID, plan.ID, w); err != nil {
				return nil, err
			}
			res.Outcome = "updated"
		case "delete":
			if err := client.DeleteSSID(ctx, siteID, plan.ID); err != nil {
				return nil, err
			}
			res.Outcome = "deleted"
		}
		return res, nil
	})
}
