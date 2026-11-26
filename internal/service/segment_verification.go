package service

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"

	"github.com/jpvelasco/nyx/internal/audit"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	fw "github.com/jpvelasco/nyx/internal/providers/opnsense"
)

// Select the two declared service checks and their positive controls. Discovery,
// unrelated assertions and agent-chosen paths never enter this verification run.
func segmentVerificationSpec(spec *intent.Spec, r SegmentRequest) (*intent.Spec, netip.Addr, error) {
	var source netip.Addr
	subnet, _ := netip.ParsePrefix(r.Gateway)
	mgmt, _ := netip.ParsePrefix(r.Management)
	resolver, _ := netip.ParseAddr(r.Resolver)
	start, _ := netip.ParseAddr(r.Start)
	end, _ := netip.ParseAddr(r.End)
	matching := false
	for _, n := range spec.Networks {
		if n.Name == r.Role {
			p, err := netip.ParsePrefix(n.CIDR)
			matching = err == nil && p.Masked() == subnet.Masked() && n.VLAN == r.Tag
			break
		}
	}
	if !matching {
		return nil, source, errors.New("verification spec must declare the requested network role, tag and subnet")
	}
	bindings, err := spec.BindServicePolicies()
	if err != nil {
		return nil, source, err
	}
	selected := *spec
	selected.ServicePolicies = nil
	selected.Assertions = nil
	seen := map[string]bool{}
	names := map[string]bool{}
	for i, b := range bindings {
		a := spec.Assertions[b.Measurement]
		probe := spec.ProbeByName(a.Runner)
		if probe == nil || probe.VLAN != r.Role {
			continue
		}
		kind := ""
		switch {
		case a.Type == "dns_check" && b.Expected == "allow" && b.Destination == resolver:
			kind = "resolver"
		case a.Type == "port_check" && b.Expected == "deny" && mgmt.Contains(b.Destination):
			kind = "management"
		default:
			continue
		}
		host, err := netip.ParseAddr(probe.Host)
		if err != nil || !inPool(host, start, end) || (source.IsValid() && source != host) || seen[kind] {
			return nil, source, errors.New("select one DNS and one management service check from the same declared source probe in the DHCP pool")
		}
		source = host
		seen[kind] = true
		selected.ServicePolicies = append(selected.ServicePolicies, spec.ServicePolicies[i])
		for _, idx := range []int{b.Measurement, b.PositiveControl} {
			check := spec.Assertions[idx]
			if !names[check.Name] {
				selected.Assertions = append(selected.Assertions, check)
				names[check.Name] = true
			}
		}
	}
	if len(seen) != 2 {
		return nil, source, errors.New("declare both resolver access and a denied management service with their positive controls")
	}
	return &selected, source, nil
}
func (e *segmentProviders) verify(bool) (string, error) {
	path := os.Getenv("NYX_SEGMENT_VERIFICATION_SPEC")
	if path == "" {
		return "manual", nil
	}
	spec, err := intent.LoadSpec(path)
	if err != nil {
		return "", err
	}
	selected, source, err := segmentVerificationSpec(spec, e.req)
	if err != nil {
		return "", err
	}
	if e.preview {
		return "planned", nil
	}
	leases, err := e.router.client(e.firewall).GetDHCPLeases(e.ctx)
	if err != nil {
		return "", err
	}
	if !slices.ContainsFunc(leases, func(l fw.DHCPLease) bool { a, _ := netip.ParseAddr(l.IP); return a == source }) {
		return "", errors.New("no active lease for the declared source probe was observed")
	}
	run := e.audit
	if run == nil {
		run = func(ctx context.Context, spec *intent.Spec) (*models.AuditReport, error) {
			return audit.NewEngine(spec).Run(ctx)
		}
	}
	return verifySegmentServices(e.ctx, selected, run)
}
func verifySegmentServices(ctx context.Context, spec *intent.Spec, run func(context.Context, *intent.Spec) (*models.AuditReport, error)) (string, error) {
	report, err := run(ctx, spec)
	if err != nil {
		return "", err
	}
	passed := 0
	for _, f := range report.Findings {
		if f.CheckType == "service_policy" {
			if f.Status != models.StatusPass {
				return "", fmt.Errorf("%s: %s", f.Target, f.Summary)
			}
			passed++
		}
	}
	if passed != len(spec.ServicePolicies) || passed != 2 {
		return "", errors.New("verification did not return both source measurements")
	}
	return "verified", nil
}
