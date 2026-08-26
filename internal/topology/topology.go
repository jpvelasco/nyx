// Package topology derives a device's NAT role and a site-level double-NAT
// assessment from facts observed through the provider APIs. It is pure: no
// network I/O, no credentials, and no live hostnames/IPs — so it can be
// unit-tested exhaustively and its output is safe to print.
//
// The motivating case: an Omada gateway (which source-NATs its LANs) sits
// upstream of an OPNsense box that is meant to be a transparent proxy. If the
// OPNsense box is also source-NATing, outbound traffic is rewritten twice
// (double NAT). This package exists so the CLI/MCP can read the facts and
// reason about the topology instead of the operator eyeballing it.
package topology

import (
	"strconv"
	"strings"
)

// NatRole is the classification of how one device participates in source NAT.
type NatRole string

const (
	// RoleNatRouter: the device performs source NAT — it is a router with a
	// private LAN behind it and a public-facing upstream.
	RoleNatRouter NatRole = "nat_router"

	// RoleBridge: the device is transparent for outbound traffic — it does
	// not source-NAT (e.g. OPNsense in line with source NAT disabled, or
	// bridged).
	RoleBridge NatRole = "bridge"

	// RoleUnknown: not enough observed facts to classify the device.
	RoleUnknown NatRole = "unknown"

	// RoleIndeterminate: the observed facts conflict (e.g. automatic source
	// NAT is disabled but explicit source-NAT rules exist).
	RoleIndeterminate NatRole = "indeterminate"
)

// NatMode constants for the OPNsense outbound (source) NAT mode, as read from
// /api/firewall/filter_base/get (filter general.snat_mode).
const (
	NatModeAutomatic = "automatic"
	NatModeHybrid    = "hybrid"
	NatModeAdvanced  = "advanced"
	NatModeDisabled  = "disabled"
)

// Provider names used in facts and reports. They are stable strings, not the
// live controller model or ID.
const (
	ProviderOmada    = "omada"
	ProviderOpnsense = "opnsense"
)

// DeviceFacts holds the NAT-relevant observations for one device. Only
// fields that the provider APIs expose are populated; the rest stay at their
// zero value. No IPs, MACs, hostnames, or controller identifiers.
type DeviceFacts struct {
	Provider string // ProviderOmada | ProviderOpnsense

	// OutboundNatMode is the OPNsense outbound (source) NAT mode. Empty for
	// providers that do not expose it (e.g. Omada).
	OutboundNatMode string

	// SourceNatRules is the count of explicit source-NAT rules on the device.
	SourceNatRules int

	// PortForwardRules is the count of destination-NAT (port-forward) rules.
	PortForwardRules int

	// OneToOneRules is the count of one-to-one NAT rules.
	OneToOneRules int

	// HasManagedGateway reports whether the site has a managed gateway device
	// (Omada). A managed gateway is a router that source-NATs its LANs.
	HasManagedGateway bool
}

// explicitNatReports counts the explicit NAT rules and reports the breakdown.
func (f DeviceFacts) explicitNatReports() string {
	parts := []string{}
	if f.SourceNatRules > 0 {
		parts = append(parts, strconv.Itoa(f.SourceNatRules)+" source-NAT rule(s)")
	}
	if f.PortForwardRules > 0 {
		parts = append(parts, strconv.Itoa(f.PortForwardRules)+" port-forward rule(s)")
	}
	if f.OneToOneRules > 0 {
		parts = append(parts, strconv.Itoa(f.OneToOneRules)+" one-to-one rule(s)")
	}
	if len(parts) == 0 {
		return "no explicit NAT rules"
	}
	return strings.Join(parts, ", ")
}

// IsRole reports whether s names one of the classifiable NatRole values
// (nat_router, bridge, indeterminate). It is the gate for expected values
// that ask for a classification rather than an outbound-mode equality or
// the "unknown"/"present" specials. RoleUnknown is excluded: a missing
// mode is key drift, not a classifiable role.
func IsRole(s string) bool {
	switch NatRole(s) {
	case RoleNatRouter, RoleBridge, RoleIndeterminate:
		return true
	}
	return false
}

// Classify derives the NAT role of a single device from its observed facts.
// It returns the role and a short evidence trail (safe to print).
//
// The decisive signal for a device that exposes it is the outbound (source)
// NAT mode: a NAT-generating mode makes it a router, "disabled" makes it
// transparent for outbound traffic. Explicit source-NAT rules override a
// "disabled" mode (they still rewrite sources), which is the indeterminate
// case. When no mode is exposed, rule counts and managed-gateway presence
// stand in.
func Classify(f DeviceFacts) (NatRole, []string) {
	switch f.Provider {
	case ProviderOpnsense:
		return classifyOpnsense(f)
	case ProviderOmada:
		return classifyOmada(f)
	default:
		return RoleUnknown, []string{"unknown provider: cannot classify"}
	}
}

func classifyOpnsense(f DeviceFacts) (NatRole, []string) {
	switch f.OutboundNatMode {
	case "":
		// Could not read the mode — fall back to rule evidence.
		switch {
		case f.SourceNatRules > 0:
			return RoleNatRouter, []string{"outbound NAT mode unavailable", f.explicitNatReports()}
		case f.SourceNatRules == 0 && f.PortForwardRules == 0 && f.OneToOneRules == 0:
			return RoleUnknown, []string{"outbound NAT mode unavailable and no NAT rules observed"}
		default:
			// Only destination NAT (port forwards / one-to-one) and no source
			// NAT: the device does not double-NAT outbound, but it is a NAT
			// appliance, so report it as a router with the caveat.
			return RoleNatRouter, []string{"outbound NAT mode unavailable", f.explicitNatReports()}
		}

	case NatModeDisabled:
		if f.SourceNatRules > 0 {
			return RoleIndeterminate, []string{
				"outbound NAT mode is disabled but " + strconv.Itoa(f.SourceNatRules) + " explicit source-NAT rule(s) exist",
			}
		}
		evidence := []string{"outbound NAT mode is disabled (no automatic source NAT)"}
		if f.explicitNatReports() != "no explicit NAT rules" {
			evidence = append(evidence, f.explicitNatReports())
		}
		return RoleBridge, evidence

	default:
		// automatic / hybrid / advanced (or an unrecognised value that is not
		// "disabled" — treated conservatively as NATing).
		evidence := []string{"outbound NAT mode is " + f.OutboundNatMode + " (generates source NAT)"}
		if f.explicitNatReports() != "no explicit NAT rules" {
			evidence = append(evidence, f.explicitNatReports())
		}
		return RoleNatRouter, evidence
	}
}

func classifyOmada(f DeviceFacts) (NatRole, []string) {
	if !f.HasManagedGateway {
		if f.PortForwardRules > 0 || f.OneToOneRules > 0 || f.SourceNatRules > 0 {
			// NAT rules with no managed gateway: a third-party gateway is
			// likely doing NAT, but we cannot confirm the role.
			return RoleIndeterminate, []string{"no managed gateway observed", f.explicitNatReports()}
		}
		return RoleUnknown, []string{"no managed gateway and no NAT rules observed"}
	}
	// A managed Omada gateway is a router that source-NATs its LANs.
	evidence := []string{"managed gateway present (routes and source-NATs its LANs)"}
	if f.explicitNatReports() != "no explicit NAT rules" {
		evidence = append(evidence, f.explicitNatReports())
	}
	return RoleNatRouter, evidence
}

// DoubleNatRisk is the site-level verdict: when two NAT devices sit in the
// path of the same LANs, outbound traffic is rewritten more than once and
// remote reachability (and, where relevant, reverse connectivity) breaks.
type DoubleNatRisk string

const (
	// RiskNone: at most one device in the observed path performs source NAT.
	RiskNone DoubleNatRisk = "none"

	// RiskDouble: two or more devices in the observed path perform source
	// NAT (or an indeterminate device may be one).
	RiskDouble DoubleNatRisk = "double_nat"

	// RiskIndeterminate: the facts cannot rule double NAT in or out.
	RiskIndeterminate DoubleNatRisk = "indeterminate"
)

// Report is the topology assessment of the observed devices.
type Report struct {
	Devices []DeviceReport `json:"devices"`
	// Risk is the double-NAT verdict for the site as a whole.
	Risk DoubleNatRisk `json:"risk"`
	// Reason explains the risk verdict in plain, printable terms.
	Reason string `json:"reason"`
}

// DeviceReport is the classified role of one device plus its evidence.
type DeviceReport struct {
	Provider string   `json:"provider"`
	Role     NatRole  `json:"role"`
	Evidence []string `json:"evidence"`
}

// BuildReport classifies every device and derives the site's double-NAT risk.
// The risk is "double_nat" when two or more observed devices would source-NAT
// the same traffic; an indeterminate device counts as a potential second
// NAT point (conservative), but two unknowns alone only yield "indeterminate".
func BuildReport(facts []DeviceFacts) *Report {
	rep := &Report{Devices: make([]DeviceReport, 0, len(facts))}
	nats, indets := 0, 0
	for _, f := range facts {
		role, evidence := Classify(f)
		rep.Devices = append(rep.Devices, DeviceReport{Provider: f.Provider, Role: role, Evidence: evidence})
		switch role {
		case RoleNatRouter:
			nats++
		case RoleIndeterminate:
			indets++
		}
	}
	switch {
	case nats >= 2:
		rep.Risk = RiskDouble
		rep.Reason = strconv.Itoa(nats) + " observed devices perform source NAT; outbound traffic will be rewritten more than once"
	case nats == 1 && indets > 0:
		rep.Risk = RiskDouble
		rep.Reason = "one device performs source NAT and at least one other is indeterminate; verify the " +
			"indeterminate device is not source-NATing (double NAT risk)"
	case nats == 0 && indets >= 1:
		rep.Risk = RiskIndeterminate
		rep.Reason = "no confirmed source-NAT device, but the NAT posture of at least one device is indeterminate"
	default:
		rep.Risk = RiskNone
		rep.Reason = "at most one device performs source NAT; no double NAT observed"
	}
	return rep
}
