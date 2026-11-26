package service

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/topology"
)

// SegmentRequest describes an IPv4 access segment in a selected Omada site behind OPNsense.
type SegmentRequest struct {
	Role       string `json:"role"`
	Tag        int    `json:"tag"`
	Parent     string `json:"parent"`
	Gateway    string `json:"gateway"`
	Management string `json:"management_prefix"`
	Resolver   string `json:"resolver"`
	Start      string `json:"pool_start"`
	End        string `json:"pool_end"`
	SSID       string `json:"ssid,omitempty"`
}

var segmentRole = regexp.MustCompile(`^[a-z][a-z0-9-]{0,30}$`)

func (r SegmentRequest) Validate() error {
	if !segmentRole.MatchString(r.Role) || r.Role == "management" || r.Tag < 1 || r.Tag > 4094 || strings.TrimSpace(r.Parent) == "" {
		return errors.New("provide a non-management role, VLAN tag 1–4094 and parent interface")
	}
	gw, eg := netip.ParsePrefix(r.Gateway)
	mgmt, em := netip.ParsePrefix(r.Management)
	dns, ed := netip.ParseAddr(r.Resolver)
	start, es := netip.ParseAddr(r.Start)
	end, ee := netip.ParseAddr(r.End)
	if eg != nil || em != nil || ed != nil || es != nil || ee != nil || !privateIPv4Subnet(gw) || !privateIPv4Subnet(mgmt) || mgmt != mgmt.Masked() || gw.Overlaps(mgmt) || !dns.Is4() || !dns.IsGlobalUnicast() || mgmt.Contains(dns) {
		return errors.New("provide separate private IPv4 segment and management networks and an IPv4 resolver outside management")
	}
	if !usableHost(gw, gw.Addr()) || !usableHost(gw, start) || !usableHost(gw, end) || start.Compare(end) > 0 || inPool(gw.Addr(), start, end) || inPool(dns, start, end) {
		return errors.New("provide a usable gateway and an ordered DHCP pool in its subnet that excludes the gateway and resolver")
	}
	return nil
}

func privateIPv4Subnet(p netip.Prefix) bool {
	if !p.Addr().Is4() || !p.Masked().Addr().IsPrivate() {
		return false
	}
	last := p.Masked().Addr().As4()
	for bit := p.Bits(); bit < 32; bit++ {
		last[bit/8] |= 1 << (7 - bit%8)
	}
	return netip.AddrFrom4(last).IsPrivate()
}

func usableHost(p netip.Prefix, a netip.Addr) bool {
	return p.Contains(a) && a != p.Masked().Addr() && p.Contains(a.Next())
}
func inPool(a, start, end netip.Addr) bool {
	return a.IsValid() && a.Compare(start) >= 0 && a.Compare(end) <= 0
}

type SegmentStep struct {
	Name      string   `json:"name"`
	Owner     string   `json:"owner"`
	DependsOn []string `json:"depends_on,omitempty"`
	Status    string   `json:"status"`
	Detail    string   `json:"detail,omitempty"`
}
type SegmentReport struct {
	Role       string        `json:"role"`
	DryRun     bool          `json:"dry_run"`
	Management string        `json:"management_impact"`
	Steps      []SegmentStep `json:"steps"`
}

// Attention identifies a blocked preview or the first unfinished step of a real apply.
func (r *SegmentReport) Attention() error {
	for _, step := range r.Steps {
		if step.Status == "review" || !r.DryRun && !segmentComplete(step.Status) {
			return fmt.Errorf("segment step %s requires attention (%s)", step.Name, step.Status)
		}
	}
	return nil
}

func segmentComplete(status string) bool {
	return status == "unchanged" || status == "applied" || status == "verified"
}

type segmentOperation struct {
	SegmentStep
	run func(bool) (string, error)
}

// runSegment preserves observations after a partial failure. Each provider reads
// current configuration again before a write. Never replay an uncertain write.
func runSegment(report *SegmentReport, operations []segmentOperation) {
	complete := map[string]bool{}
	for _, op := range operations {
		step := op.SegmentStep
		step.Status = "waiting"
		ready := true
		for _, dep := range step.DependsOn {
			if !complete[dep] {
				ready = false
				break
			}
		}
		if ready {
			action, err := op.run(true)
			step.Status = action
			if err == nil && !report.DryRun && (action == "create" || action == "assign") {
				_, writeErr := op.run(false)
				observed, readErr := op.run(true)
				switch {
				case writeErr != nil:
					err = fmt.Errorf("apply interrupted; observed %q on readback: %w", observed, writeErr)
				case readErr != nil:
					err = fmt.Errorf("readback failed: %w", readErr)
				case observed != "unchanged":
					err = fmt.Errorf("readback returned %q", observed)
				default:
					step.Status = "applied"
				}
			}
			if err != nil {
				step.Status = "review"
				step.Detail = err.Error()
			}
		}
		complete[step.Name] = segmentComplete(step.Status)
		report.Steps = append(report.Steps, step)
	}
}

func preserveExisting(createOnly bool, action string) error {
	if createOnly && action != "create" && action != "unchanged" {
		return fmt.Errorf("existing configuration differs; review the %s plan", action)
	}
	return nil
}

type segmentAudit func(context.Context, *intent.Spec) (*models.AuditReport, error)

type SegmentService struct {
	Topology TopologySurface
	audit    segmentAudit
}

// Reconcile selects owners before configuring a new segment. Manual steps and partial
// observations stay in the report, so a subsequent run resumes from the controllers.
func (s SegmentService) Reconcile(ctx context.Context, opts PlaybookOptions, r SegmentRequest, dry bool) (*SegmentReport, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	if opts.Omada == nil || opts.Opnsense == nil || opts.Omada.Site == "" {
		return nil, errors.New("segment planning requires an explicitly selected Omada site and OPNsense firewall")
	}
	topo, err := s.Topology.Report(ctx, TopologyOptions{Omada: opts.Omada, Opnsense: opts.Opnsense})
	if err != nil {
		return nil, err
	}
	owner, found, ambiguous := natOwnerFromReport(topo)
	if !found || ambiguous || owner != "opnsense" || topology.DoubleNatRisk(topo.Risk) == topology.RiskDouble {
		return nil, errors.New("routing owner is uncertain; select the segment router manually")
	}
	report := &SegmentReport{Role: r.Role, DryRun: dry, Management: "Preserve existing assignments and filter rules. Block this source subnet from management before configuring client access."}
	env := segmentProviders{ctx: ctx, omada: *opts.Omada, firewall: *opts.Opnsense, req: r, preview: dry, audit: s.audit, switchAPI: NewOmadaService(), router: NewOpnsenseService()}
	runSegment(report, env.operations())
	return report, nil
}
