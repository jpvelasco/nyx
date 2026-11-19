package audit

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jpvelasco/nyx/internal/backends/nmap"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
)

func (e *Engine) runDiscovery(ctx context.Context, a intent.Assertion) (*models.CheckResult, error) {
	net := e.Spec.NetworkByName(a.Network)
	if net == nil {
		return nil, fmt.Errorf("network %q not found in spec", a.Network)
	}

	// Build scan options — default to polite scan mode, use assertion overrides if set.
	opts := nmap.ScanOptionsForMode(nmap.ScanModePolite)
	if a.ScanMode != "" {
		opts = nmap.ScanOptionsForMode(nmap.ScanMode(a.ScanMode))
	}
	if a.ScanTiming > 0 {
		opts.TimingTemplate = a.ScanTiming
	}
	if a.ScanMinRate > 0 {
		opts.MinRate = a.ScanMinRate
	}
	// ARP for directly-attached networks, ICMP echo for routed ones, so the
	// sweep never relies on nmap's default probe set.
	probeSet, err := nmap.ChooseProbeSet(net.CIDR)
	if err != nil {
		return nil, err
	}
	opts.ProbeSet = probeSet

	result, err := e.Backend.Discover(ctx, net.CIDR, opts)
	if err != nil {
		return nil, fmt.Errorf("nmap discovery failed: %w", err)
	}

	// Populate expected bounds in result metadata before evaluating
	if a.ExpectHostsMin != nil {
		result.Expected["expect_hosts_min"] = *a.ExpectHostsMin
	}
	if a.ExpectHostsMax != nil {
		result.Expected["expect_hosts_max"] = *a.ExpectHostsMax
	}

	// Evaluate host count assertions.
	// The nmap backend puts the host count under "total" in Observed.
	hostCount := 0
	if v, ok := result.Observed["total"]; ok {
		switch n := v.(type) {
		case int:
			hostCount = n
		case float64:
			hostCount = int(n)
		}
	}

	if a.ExpectHostsMax != nil && hostCount > *a.ExpectHostsMax {
		result.Status = models.StatusFail
		result.Violations = append(result.Violations,
			fmt.Sprintf("found %d hosts, expected max %d", hostCount, *a.ExpectHostsMax))
	}
	if a.ExpectHostsMin != nil && hostCount < *a.ExpectHostsMin {
		result.Status = models.StatusFail
		result.Violations = append(result.Violations,
			fmt.Sprintf("found %d hosts, expected min %d", hostCount, *a.ExpectHostsMin))
	}

	// Host count violations take precedence over virtual network detection —
	// a real host-count failure should not be silently downgraded to a virtual
	// network warning.
	if len(result.Violations) > 0 {
		result.Summary = fmt.Sprintf("%d hosts discovered in %s", hostCount, net.CIDR)
		result.Finish()
		return result, nil
	}

	// Virtual network suppression: if 0 hosts and nmap evidence suggests a VM
	// hypervisor MAC, check seendb. First occurrence → WARN + ack. Subsequent
	// occurrences → SKIP (unless WarnVirtual override is set).
	// Check this BEFORE setting default pass status so the flow is clearer.
	if hostCount == 0 && (looksVirtual(result.Evidence) || looksVirtualByCIDR(net.CIDR)) {
		cidr := net.CIDR
		if e.WarnVirtual || !e.seenDB.IsVirtualAcked(cidr) {
			result.Status = models.StatusWarn
			if e.WarnVirtual {
				result.Summary = fmt.Sprintf("0 hosts discovered in %s (virtual adapter detected; --warn-virtual is set)", cidr)
			} else {
				result.Summary = fmt.Sprintf("0 hosts discovered in %s (virtual adapter detected — future scans will suppress this warning; use --warn-virtual to always show it)", cidr)
			}
			if err := e.seenDB.AckVirtual(cidr); err != nil {
				// Log the spec's network role name, never the CIDR — the
				// log file is a shareable artifact (docs/naming.md).
				e.Logger.Warn("failed to ack virtual network; warning will reappear on next run", slog.String("network", net.Name), slog.String("error", err.Error()))
				result.Evidence = append(result.Evidence, fmt.Sprintf("warning: failed to persist virtual network ack for %s: %v", cidr, err))
			}
		} else {
			result.Status = models.StatusSkip
			result.Summary = fmt.Sprintf("skipped: %s is a virtual network (acknowledged)", cidr)
		}
		result.Finish()
		return result, nil
	}

	if result.Status == "" || (len(result.Violations) == 0 &&
		result.Status != models.StatusError &&
		result.Status != models.StatusWarn) {
		result.Status = models.StatusPass
	}

	result.Summary = fmt.Sprintf("%d hosts discovered in %s", hostCount, net.CIDR)
	return result, nil
}
