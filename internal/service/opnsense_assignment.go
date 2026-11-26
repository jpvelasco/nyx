package service

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	fw "github.com/jpvelasco/nyx/internal/providers/opnsense"
)

var assignmentName = regexp.MustCompile(`^[A-Za-z0-9_]{1,255}$`)

// The assignment API applies the entire staged queue. Compare the complete
// inventory before and after staging, including identifiers that disappear
// from search_item immediately when another operator stages their deletion.
type assignmentView struct {
	rows    []fw.Assignment
	pending bool
}

func readAssignmentView(ctx context.Context, c *fw.Client) (assignmentView, error) {
	rows, err := c.Assignments(ctx)
	if err != nil {
		return assignmentView{}, err
	}
	pending, err := c.AssignmentsPending(ctx)
	return assignmentView{rows, pending}, err
}

func (v assignmentView) onlyAdded(previous assignmentView, id string) bool {
	if !v.pending || len(v.rows) != len(previous.rows)+1 {
		return false
	}
	before := make(map[string]fw.Assignment, len(previous.rows))
	for _, row := range previous.rows {
		before[row.Identifier] = row
	}
	for _, row := range v.rows {
		if row.Identifier == id {
			if row.Pending != "update" {
				return false
			}
			continue
		}
		if old, ok := before[row.Identifier]; !ok || old != row {
			return false
		}
	}
	return true
}

// OpnsenseAssignmentTarget identifies the selected VLAN and static interface address.
type OpnsenseAssignmentTarget struct {
	Parent  string `json:"parent"`
	Tag     int    `json:"tag"`
	Device  string `json:"device"`
	Name    string `json:"name"`
	Address string `json:"address"`
	Family  string `json:"family"`
}

type vlanAssignment struct {
	device, name string
	address      netip.Prefix
}

func assignmentTarget(ctx context.Context, c *fw.Client, req OpnsenseVLANRequest) (vlanAssignment, error) {
	p, err := netip.ParsePrefix(req.Address)
	if err != nil || !p.Addr().IsGlobalUnicast() || p.Addr().Is4In6() || p.Bits() == 0 {
		return vlanAssignment{}, errors.New("assignment requires a unicast static interface address with a prefix length")
	}
	if p.Addr().Is4() && p.Bits() < 31 && (p.Masked().Addr() == p.Addr() || !p.Contains(p.Addr().Next())) {
		return vlanAssignment{}, errors.New("IPv4 interface address must be a usable host in the requested subnet")
	}
	if req.Tag < 1 || req.Tag > 4094 || req.Parent == "" || !assignmentName.MatchString(req.Description) || req.UUID != "" || req.Delete || len(req.Members) > 0 {
		return vlanAssignment{}, errors.New("assignment requires a VLAN parent, tag and interface description and accepts no UUID, delete or bridge members")
	}
	vlans, err := c.AssignmentVLANs(ctx)
	if err != nil {
		return vlanAssignment{}, err
	}
	target := vlanAssignment{name: req.Description, address: p}
	for _, v := range vlans {
		if v.Parent != req.Parent || v.Tag != req.Tag {
			continue
		}

		device, _, _ := strings.Cut(v.Device, " [")
		if target.device != "" || device == "" || device == req.Parent {
			return vlanAssignment{}, errors.New("ambiguous VLAN device identity")
		}
		target.device = device
	}
	if target.device == "" {
		return target, errors.New("create and verify the selected VLAN device before assigning it")
	}
	return target, nil
}

func (t vlanAssignment) match(row fw.Assignment) bool {
	mode, address := row.Type4, row.Addr4
	expected := "staticv4"
	if t.address.Addr().Is6() {
		mode, address, expected = row.Type6, row.Addr6, "staticv6"
	}
	p, err := netip.ParsePrefix(address)
	return err == nil && p == t.address && mode == expected && row.Enable == "1" && row.Device == t.device && row.Description == t.name
}

func (t vlanAssignment) inspect(v assignmentView) (string, error) {
	id := ""
	for _, row := range v.rows {
		if row.Device == t.device || strings.EqualFold(row.Description, t.name) {
			if id != "" || !t.match(row) {
				return "", errors.New("assignment conflicts with an existing interface; its configuration was preserved")
			}
			id = row.Identifier
			continue
		}
		for _, other := range []string{row.Addr4, row.Addr6} {
			if other == "" {
				continue
			}
			p, err := netip.ParsePrefix(other)
			if err != nil {
				return "", errors.New("cannot verify existing interface address prefixes")
			}
			if p.Overlaps(t.address) {
				return "", errors.New("requested assignment overlaps another interface network")
			}
		}
	}
	return id, nil
}

// Check active routes as DHCP, delegated IPv6 and static routes can reach
// networks absent from the configured static interface addresses.
func (t vlanAssignment) checkRoutes(ctx context.Context, c *fw.Client) error {
	routes, err := c.GetKernelRoutes(ctx)
	if err != nil {
		return err
	}
	if len(routes) == 0 {
		return errors.New("cannot verify active routes before VLAN assignment")
	}
	for _, route := range routes {
		if route.Destination == "default" {
			continue
		}
		p, ok := assignmentRoute(route.Destination)
		if !ok {
			return errors.New("cannot verify an active route prefix")
		}
		if p.Bits() > 0 && p.Overlaps(t.address) {
			return errors.New("requested assignment overlaps an active route; review management reachability")
		}
	}
	return nil
}

// FreeBSD adds interface zones to IPv6 link-local destinations, including
// prefixes. The zone does not change the address range used for overlap checks.
func assignmentRoute(raw string) (netip.Prefix, bool) {
	host, width, subnet := strings.Cut(raw, "/")
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Prefix{}, false
	}
	bits := addr.BitLen()
	if subnet {
		bits, err = strconv.Atoi(width)
		if err != nil {
			return netip.Prefix{}, false
		}
	}
	prefix := netip.PrefixFrom(addr.WithZone(""), bits)
	return prefix, prefix.IsValid()
}

func planAssignment(ctx context.Context, c *fw.Client, req OpnsenseVLANRequest) (*OpnsenseVLANPlan, vlanAssignment, assignmentView, error) {
	plan := &OpnsenseVLANPlan{Kind: "assignment"}
	target, err := assignmentTarget(ctx, c, req)
	if err != nil {
		return nil, target, assignmentView{}, err
	}
	family := "ipv4"
	if target.address.Addr().Is6() {
		family = "ipv6"
	}
	plan.Assignment = &OpnsenseAssignmentTarget{Parent: req.Parent, Tag: req.Tag, Device: target.device, Name: target.name, Address: target.address.String(), Family: family}
	view, err := readAssignmentView(ctx, c)
	if errors.Is(err, fw.ErrAssignmentUnavailable) {
		plan.Action = "manual"
		plan.Warning = err.Error()
		return plan, target, view, nil
	}
	if err != nil {
		return nil, target, view, err
	}
	id, err := target.inspect(view)
	if err != nil {
		return nil, target, view, err
	}
	plan.UUID = id
	switch {
	case view.pending:
		plan.Action = "manual"
		plan.Warning = "Interface changes are already staged. Review the pending queue in the GUI and retry after applying or discarding it."
	case id != "":
		plan.Action = "unchanged"
	default:
		if err := target.checkRoutes(ctx, c); err != nil {
			return nil, target, view, err
		}
		plan.Action = "assign"
	}
	return plan, target, view, nil
}

func runAssignment(ctx context.Context, c *fw.Client, req OpnsenseVLANRequest, dryRun bool) (*OpnsenseVLANApplyResult, error) {
	plan, target, before, err := planAssignment(ctx, c, req)
	if err != nil {
		return nil, err
	}
	res := plan.result(dryRun)
	if dryRun || plan.Action != "assign" {
		return res, nil
	}
	id, err := c.StageAssignment(ctx, target.device, target.name, target.address)
	if err != nil {
		return nil, fmt.Errorf("staging interface assignment; re-read the plan before retrying: %w", err)
	}
	staged, err := readAssignmentView(ctx, c)
	if err != nil {
		return nil, err
	}
	stagedID, err := target.inspect(staged)
	if err != nil {
		return nil, err
	}
	if id != stagedID || !staged.onlyAdded(before, id) {
		return nil, errors.New("staged assignments changed; review the pending queue before activating it")
	}
	if err := c.ActivateAssignments(ctx); err != nil {
		return nil, fmt.Errorf("assignment activation uncertain; re-read the plan before retrying: %w", err)
	}
	after, err := readAssignmentView(ctx, c)
	if err != nil {
		return nil, err
	}
	actual, err := target.inspect(after)
	if err != nil {
		return nil, err
	}
	if after.pending || actual != id {
		return nil, errors.New("assignment activation could not be verified by readback")
	}
	res.Outcome = "assigned"
	res.UUID = id
	return res, nil
}
