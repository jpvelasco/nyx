package service

import (
	"context"
	"fmt"
	"strings"

	opnsensebackend "github.com/jpvelasco/nyx/internal/providers/opnsense"
)

// OpnsenseDnsmasqSettings is the observe subset of Dnsmasq settings.
type OpnsenseDnsmasqSettings struct {
	Enabled    bool                   `json:"enabled"`
	Interfaces []string               `json:"interfaces,omitempty"`
	Ranges     []OpnsenseDnsmasqRange `json:"ranges,omitempty"`
	Hosts      []OpnsenseDnsmasqHost  `json:"hosts,omitempty"`
}

// OpnsenseDnsmasqRange is one DHCP range.
type OpnsenseDnsmasqRange struct {
	UUID      string `json:"uuid,omitempty"`
	Interface string `json:"interface,omitempty"`
	Start     string `json:"start,omitempty"`
	End       string `json:"end,omitempty"`
}

// OpnsenseDnsmasqHost is one static host mapping.
type OpnsenseDnsmasqHost struct {
	UUID   string `json:"uuid,omitempty"`
	Host   string `json:"host,omitempty"`
	Domain string `json:"domain,omitempty"`
	IP     string `json:"ip,omitempty"`
}

// GetDnsmasqSettings returns Dnsmasq enable/interfaces/ranges/hosts.
func (s *OpnsenseService) GetDnsmasqSettings(ctx context.Context, opts OpnsenseOptions) (*OpnsenseDnsmasqSettings, error) {
	client := s.client(opts)
	got, err := client.GetDnsmasqSettings(ctx)
	if err != nil {
		return nil, err
	}
	return flattenDnsmasq(got), nil
}

// OpnsenseKeaSubnet is one Kea DHCPv4 subnet.
type OpnsenseKeaSubnet struct {
	UUID        string `json:"uuid"`
	Subnet      string `json:"subnet"`
	Description string `json:"description,omitempty"`
}

// OpnsenseKeaReservation is one Kea static mapping.
type OpnsenseKeaReservation struct {
	UUID     string `json:"uuid"`
	IP       string `json:"ip,omitempty"`
	MAC      string `json:"mac,omitempty"`
	Hostname string `json:"hostname,omitempty"`
}

// ListKeaSubnets returns Kea DHCPv4 subnets.
func (s *OpnsenseService) ListKeaSubnets(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseKeaSubnet, error) {
	got, err := s.client(opts).GetKeaSubnets(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]OpnsenseKeaSubnet, len(got))
	for i, x := range got {
		out[i] = OpnsenseKeaSubnet{UUID: x.UUID, Subnet: x.Subnet, Description: x.Description}
	}
	return out, nil
}

// ListKeaReservations returns Kea DHCPv4 reservations.
func (s *OpnsenseService) ListKeaReservations(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseKeaReservation, error) {
	got, err := s.client(opts).GetKeaReservations(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]OpnsenseKeaReservation, len(got))
	for i, x := range got {
		out[i] = OpnsenseKeaReservation{UUID: x.UUID, IP: x.IP, MAC: x.MAC, Hostname: x.Hostname}
	}
	return out, nil
}

func flattenDnsmasq(in *opnsensebackend.DnsmasqSettings) *OpnsenseDnsmasqSettings {
	if in == nil {
		return nil
	}
	out := &OpnsenseDnsmasqSettings{Enabled: in.Enabled, Interfaces: in.Interfaces}
	for _, r := range in.Ranges {
		out.Ranges = append(out.Ranges, OpnsenseDnsmasqRange{UUID: r.UUID, Interface: r.Interface, Start: r.Start, End: r.End})
	}
	for _, h := range in.Hosts {
		out.Hosts = append(out.Hosts, OpnsenseDnsmasqHost{UUID: h.UUID, Host: h.Host, Domain: h.Domain, IP: h.IP})
	}
	return out
}

// OpnsenseDHCPRequest is a plan/apply DHCP range/host/reservation mutation.
type OpnsenseDHCPRequest struct {
	Backend   string // auto (default), dnsmasq, kea
	Kind      string // range, host, reservation
	Interface string
	Start     string
	End       string
	IP        string
	MAC       string
	Hostname  string
	UUID      string
	Delete    bool
}

// OpnsenseDHCPPlan previews a DHCP mutation.
type OpnsenseDHCPPlan struct {
	Action  string `json:"action"`
	Backend string `json:"backend"`
	Kind    string `json:"kind"`
	UUID    string `json:"uuid,omitempty"`

	// effHost/effRange/effReservation carry the effective update payload
	// resolved during planning: requested fields overlay the existing
	// record so omitted fields preserve it, and the apply sends exactly
	// what the plan compared — never empty strings for preserved fields.
	effHost        *opnsensebackend.DnsmasqHostWrite
	effRange       *opnsensebackend.DnsmasqRangeWrite
	effReservation *opnsensebackend.KeaReservationWrite
}

// OpnsenseDHCPApplyResult is the apply outcome.
type OpnsenseDHCPApplyResult struct {
	Outcome string `json:"outcome"`
	Backend string `json:"backend"`
	Kind    string `json:"kind"`
	UUID    string `json:"uuid,omitempty"`
	DryRun  bool   `json:"dry_run"`
}

func dhcpKind(kind string) string {
	switch strings.ToLower(kind) {
	case "host", "reservation":
		return strings.ToLower(kind)
	default:
		return "range"
	}
}

func (s *OpnsenseService) resolveDHCPBackend(ctx context.Context, opts OpnsenseOptions, want string) (string, error) {
	client := s.client(opts)
	detected, err := client.DetectDHCPBackend(ctx)
	if err != nil {
		return "", err
	}
	want = strings.ToLower(want)
	if want == "" || want == "auto" {
		return detected, nil
	}
	if want != "dnsmasq" && want != "kea" {
		return "", fmt.Errorf("backend must be auto, dnsmasq, or kea")
	}
	if want != detected {
		return "", fmt.Errorf("requested backend %s but the running backend is %s", want, detected)
	}
	return detected, nil
}

// PlanDHCP previews a Dnsmasq range/host or Kea subnet/reservation mutation.
func (s *OpnsenseService) PlanDHCP(ctx context.Context, opts OpnsenseOptions, req OpnsenseDHCPRequest) (*OpnsenseDHCPPlan, error) {
	backend, err := s.resolveDHCPBackend(ctx, opts, req.Backend)
	if err != nil {
		return nil, err
	}
	kind := dhcpKind(req.Kind)
	if backend == "kea" && kind == "host" {
		kind = "reservation"
	}
	if backend == "dnsmasq" && kind == "reservation" {
		kind = "host"
	}
	plan := &OpnsenseDHCPPlan{Backend: backend, Kind: kind, UUID: req.UUID}
	client := s.client(opts)
	if backend == "dnsmasq" {
		return planDnsmasq(ctx, client, plan, req)
	}
	return planKea(ctx, client, plan, req)
}

func planDnsmasq(ctx context.Context, client *opnsensebackend.Client, plan *OpnsenseDHCPPlan, req OpnsenseDHCPRequest) (*OpnsenseDHCPPlan, error) {
	settings, err := client.GetDnsmasqSettings(ctx)
	if err != nil {
		return nil, err
	}
	if plan.Kind == "host" {
		if !req.Delete && req.Hostname == "" && req.IP == "" && req.UUID == "" {
			return nil, fmt.Errorf("hostname and ip are required to create a static host")
		}
		cur, ok := opnsensebackend.FindDnsmasqHost(settings.Hosts, req.UUID, req.Hostname, req.IP)
		if req.Delete {
			if !ok {
				plan.Action = "unchanged"
				return plan, nil
			}
			plan.Action = "delete"
			plan.UUID = cur.UUID
			return plan, nil
		}
		if !ok {
			plan.Action = "create"
			plan.effHost = &opnsensebackend.DnsmasqHostWrite{Host: req.Hostname, IP: req.IP, MAC: req.MAC}
			return plan, nil
		}
		plan.UUID = cur.UUID
		// Resolve the effective requested values: omitted fields preserve
		// the existing record, and every writable field participates in the
		// comparison. A MAC-only change plans as an update; MAC comparison
		// is normalized (case- and spacing-insensitive) so the stored form
		// cannot mask a real change.
		eff := &opnsensebackend.DnsmasqHostWrite{
			Host: firstNonEmptySvc(req.Hostname, cur.Host),
			IP:   firstNonEmptySvc(req.IP, cur.IP),
			MAC:  firstNonEmptySvc(req.MAC, cur.MAC),
		}
		plan.effHost = eff
		if strings.EqualFold(cur.Host, eff.Host) && cur.IP == eff.IP && sameMAC(cur.MAC, eff.MAC) {
			plan.Action = "unchanged"
			return plan, nil
		}
		plan.Action = "update"
		return plan, nil
	}
	if !req.Delete && (req.Start == "" || req.End == "") && req.UUID == "" {
		return nil, fmt.Errorf("start and end are required to create a DHCP range")
	}
	cur, ok := opnsensebackend.FindDnsmasqRange(settings.Ranges, req.UUID, req.Interface, req.Start, req.End)
	if req.Delete {
		if !ok {
			plan.Action = "unchanged"
			return plan, nil
		}
		plan.Action = "delete"
		plan.UUID = cur.UUID
		return plan, nil
	}
	if !ok {
		plan.Action = "create"
		plan.effRange = &opnsensebackend.DnsmasqRangeWrite{Interface: req.Interface, Start: req.Start, End: req.End}
		return plan, nil
	}
	plan.UUID = cur.UUID
	effRange := &opnsensebackend.DnsmasqRangeWrite{
		Interface: firstNonEmptySvc(req.Interface, cur.Interface),
		Start:     firstNonEmptySvc(req.Start, cur.Start),
		End:       firstNonEmptySvc(req.End, cur.End),
	}
	plan.effRange = effRange
	if strings.EqualFold(cur.Interface, effRange.Interface) && cur.Start == effRange.Start && cur.End == effRange.End {
		plan.Action = "unchanged"
		return plan, nil
	}
	plan.Action = "update"
	return plan, nil
}

func planKea(ctx context.Context, client *opnsensebackend.Client, plan *OpnsenseDHCPPlan, req OpnsenseDHCPRequest) (*OpnsenseDHCPPlan, error) {
	if plan.Kind == "reservation" {
		if !req.Delete && (req.IP == "" || req.MAC == "") && req.UUID == "" {
			return nil, fmt.Errorf("ip and mac are required to create a Kea reservation")
		}
		rows, err := client.GetKeaReservations(ctx)
		if err != nil {
			return nil, err
		}
		cur, ok := opnsensebackend.FindKeaReservation(rows, req.UUID, req.IP, req.MAC)
		if req.Delete {
			if !ok {
				plan.Action = "unchanged"
				return plan, nil
			}
			plan.Action = "delete"
			plan.UUID = cur.UUID
			return plan, nil
		}
		if !ok {
			plan.Action = "create"
			plan.effReservation = &opnsensebackend.KeaReservationWrite{IP: req.IP, MAC: req.MAC, Hostname: req.Hostname}
			return plan, nil
		}
		plan.UUID = cur.UUID
		// Effective requested values: omitted fields preserve the existing
		// reservation; hostname changes participate in the comparison so a
		// hostname-only change plans as an update.
		eff := &opnsensebackend.KeaReservationWrite{
			IP:       firstNonEmptySvc(req.IP, cur.IP),
			MAC:      firstNonEmptySvc(req.MAC, cur.MAC),
			Hostname: firstNonEmptySvc(req.Hostname, cur.Hostname),
		}
		plan.effReservation = eff
		if cur.IP == eff.IP && sameMAC(cur.MAC, eff.MAC) && strings.EqualFold(cur.Hostname, eff.Hostname) {
			plan.Action = "unchanged"
			return plan, nil
		}
		plan.Action = "update"
		return plan, nil
	}
	subnet := req.Start
	if req.End != "" && !strings.Contains(subnet, "/") {
		subnet = req.End
	}
	if subnet == "" {
		subnet = req.Interface
	}
	if !req.Delete && subnet == "" && req.UUID == "" {
		return nil, fmt.Errorf("subnet CIDR is required to create a Kea subnet (pass it as start)")
	}
	rows, err := client.GetKeaSubnets(ctx)
	if err != nil {
		return nil, err
	}
	cur, ok := opnsensebackend.FindKeaSubnet(rows, req.UUID, subnet)
	if req.Delete {
		if !ok {
			plan.Action = "unchanged"
			return plan, nil
		}
		plan.Action = "delete"
		plan.UUID = cur.UUID
		return plan, nil
	}
	if !ok {
		plan.Action = "create"
		return plan, nil
	}
	plan.UUID = cur.UUID
	if cur.Subnet == subnet {
		plan.Action = "unchanged"
		return plan, nil
	}
	plan.Action = "update"
	return plan, nil
}

// ApplyDHCP creates/updates/deletes a DHCP range, host, or reservation.
// Dry-run issues zero POSTs. A real apply reconfigures the active backend.
func (s *OpnsenseService) ApplyDHCP(ctx context.Context, opts OpnsenseOptions, req OpnsenseDHCPRequest, dryRun bool) (*OpnsenseDHCPApplyResult, error) {
	plan, err := s.PlanDHCP(ctx, opts, req)
	if err != nil {
		return nil, err
	}
	res := &OpnsenseDHCPApplyResult{Outcome: plan.Action, Backend: plan.Backend, Kind: plan.Kind, UUID: plan.UUID, DryRun: dryRun}
	if dryRun || plan.Action == "unchanged" {
		return res, nil
	}
	client := s.client(opts)
	if plan.Backend == "dnsmasq" {
		if err := applyDnsmasq(ctx, client, plan, req, res); err != nil {
			return nil, err
		}
		if err := client.ReconfigureDnsmasq(ctx); err != nil {
			return nil, err
		}
		return res, nil
	}
	if err := applyKea(ctx, client, plan, req, res); err != nil {
		return nil, err
	}
	if err := client.ReconfigureKea(ctx); err != nil {
		return nil, err
	}
	return res, nil
}

// sameMAC compares two hardware addresses with controller-aware
// normalization: case and surrounding whitespace are insignificant, so a
// stored "02:00:00:00:00:01" and a requested "02:00:00:00:00:01" cannot
// mask a real change.
func sameMAC(a, b string) bool {
	return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

func applyDnsmasq(ctx context.Context, client *opnsensebackend.Client, plan *OpnsenseDHCPPlan, req OpnsenseDHCPRequest, res *OpnsenseDHCPApplyResult) error {
	if plan.Kind == "host" {
		switch plan.Action {
		case "create":
			// The effective payload resolved during planning drives the
			// write: omitted fields preserve the existing record's values
			// (#183). Deletes carry no payload.
			id, err := client.CreateDnsmasqHost(ctx, *plan.effHost)
			if err != nil {
				return err
			}
			res.UUID, res.Outcome = id, "created"
		case "update":
			if err := client.SetDnsmasqHost(ctx, plan.UUID, *plan.effHost); err != nil {
				return err
			}
			res.Outcome = "updated"
		case "delete":
			if err := client.DeleteDnsmasqHost(ctx, plan.UUID); err != nil {
				return err
			}
			res.Outcome = "deleted"
		}
		return nil
	}
	switch plan.Action {
	case "create":
		id, err := client.CreateDnsmasqRange(ctx, *plan.effRange)
		if err != nil {
			return err
		}
		res.UUID, res.Outcome = id, "created"
	case "update":
		if err := client.SetDnsmasqRange(ctx, plan.UUID, *plan.effRange); err != nil {
			return err
		}
		res.Outcome = "updated"
	case "delete":
		if err := client.DeleteDnsmasqRange(ctx, plan.UUID); err != nil {
			return err
		}
		res.Outcome = "deleted"
	}
	return nil
}

func applyKea(ctx context.Context, client *opnsensebackend.Client, plan *OpnsenseDHCPPlan, req OpnsenseDHCPRequest, res *OpnsenseDHCPApplyResult) error {
	if plan.Kind == "reservation" {
		switch plan.Action {
		case "create":
			// The effective payload resolved during planning drives the
			// write: omitted fields preserve the existing reservation
			// (#183). Deletes carry no payload.
			id, err := client.CreateKeaReservation(ctx, *plan.effReservation)
			if err != nil {
				return err
			}
			res.UUID, res.Outcome = id, "created"
		case "update":
			if err := client.SetKeaReservation(ctx, plan.UUID, *plan.effReservation); err != nil {
				return err
			}
			res.Outcome = "updated"
		case "delete":
			if err := client.DeleteKeaReservation(ctx, plan.UUID); err != nil {
				return err
			}
			res.Outcome = "deleted"
		}
		return nil
	}
	w := opnsensebackend.KeaSubnetWrite{Subnet: firstNonEmptySvc(req.Start, req.Interface)}
	switch plan.Action {
	case "create":
		id, err := client.CreateKeaSubnet(ctx, w)
		if err != nil {
			return err
		}
		res.UUID, res.Outcome = id, "created"
	case "update":
		if err := client.SetKeaSubnet(ctx, plan.UUID, w); err != nil {
			return err
		}
		res.Outcome = "updated"
	case "delete":
		if err := client.DeleteKeaSubnet(ctx, plan.UUID); err != nil {
			return err
		}
		res.Outcome = "deleted"
	}
	return nil
}
