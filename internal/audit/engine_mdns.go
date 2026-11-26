package audit

import (
	"context"
	"net/netip"

	"strconv"
	"strings"

	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/probe"
)

// mdnsLookup resolves exactly one declared name through the client probe's mDNS
// resolver. Raw resolver output is untrusted and never leaves this check.
func (e *Engine) mdnsLookup(ctx context.Context, a intent.Assertion, p probe.Probe) (*models.CheckResult, error) {
	if err := e.Spec.ValidateMDNSLookup(a); err != nil {
		return nil, err
	}
	addr, _ := netip.ParseAddr(a.ExpectIP)
	family := "-6"
	if addr.Is4() {
		family = "-4"
	}
	r := models.NewCheckResult("probe", "mdns_lookup", a.Runner, a.Name)
	r.Expected["address"] = addr.String()
	r.Observed["client_network"] = a.From
	r.Observed["service_network"] = a.To
	r.Observed["application_connectivity"] = "unmeasured"
	r.Observed["imported_reflection_network_scope"] = reflectionState(e.Spec, a)
	name := strings.TrimSuffix(strings.ToLower(a.Query), ".")
	output, err := probe.Run(ctx, p, []string{"avahi-resolve-host-name", family, name}, e.SkipHostKeyVerify)
	r.Status = models.StatusWarn
	r.Summary = "mDNS discovery unverified from the client probe"
	r.Observed["discovery"] = "unknown"
	if err == nil {
		for line := range strings.SplitSeq(output, "\n") {
			fields := strings.Fields(line)
			if len(fields) != 2 || !strings.EqualFold(strings.TrimSuffix(fields[0], "."), name) {
				continue
			}
			answer, err := netip.ParseAddr(fields[1])
			if err != nil || answer.Is4() != addr.Is4() {
				continue
			}
			r.Observed["discovery"] = "different_address"
			r.Status = models.StatusFail
			r.Summary = "mDNS hostname resolved to a different address"
			if answer == addr {
				r.Status = models.StatusPass
				r.Summary = "Client probe resolved the declared mDNS service address"
				r.Observed["discovery"] = "resolved"
				break
			}
		}
	}
	r.Finish()
	return r, nil
}

// Omada AP rules carry VLAN numbers directly. Gateway rules carry opaque
// IDs, which an imported role-only spec cannot reliably map to a network.
func reflectionState(spec *intent.Spec, a intent.Assertion) string {
	if spec.Inventory == nil || spec.Inventory.MDNS == nil || spec.Inventory.MDNS.Status != "available" {
		return "unknown"
	}
	client, service := spec.NetworkByName(a.From), spec.NetworkByName(a.To)
	if client == nil || service == nil || client.VLAN < 1 || service.VLAN < 1 {
		return "unknown"
	}
	state := "no_matching_rule"
	unmapped := false
	for _, rule := range spec.Inventory.MDNS.Rules {
		if rule.Type != 0 || rule.AP == nil {
			unmapped = true
			continue
		}
		from, fromKnown := vlanMembership(rule.AP.Client, client.VLAN)
		to, toKnown := vlanMembership(rule.AP.Service, service.VLAN)
		if (from || !fromKnown) && (to || !toKnown) && (!fromKnown || !toKnown) {
			unmapped = true
		}
		if from && to {
			if rule.Enabled {
				return "enabled"
			}
			state = "disabled"
		}
	}
	if unmapped {
		return "unknown"
	}
	return state
}

// Omada permits comma-separated tag numbers and inclusive ranges.
func vlanMembership(values string, tag int) (matched, known bool) {
	known = true
	for item := range strings.SplitSeq(values, ",") {
		a, b, ranged := strings.Cut(strings.TrimSpace(item), "-")
		lo, err := strconv.Atoi(strings.TrimSpace(a))
		hi := lo
		if ranged && err == nil {
			hi, err = strconv.Atoi(strings.TrimSpace(b))
		}
		if err != nil || lo < 1 || hi > 4094 || hi < lo {
			known = false
			continue
		}
		if tag >= lo && tag <= hi {
			return true, true
		}
	}
	return false, known
}
