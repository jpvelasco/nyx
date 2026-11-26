package audit

import (
	"fmt"

	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
)

// servicePolicyFinding correlates only observations produced during the same
// audit. A successful new connection says nothing about existing firewall state.
func servicePolicyFinding(spec *intent.Spec, b intent.ServicePolicyBinding, findings []models.CheckResult) models.CheckResult {
	a, c := spec.Assertions[b.Measurement], spec.Assertions[b.PositiveControl]
	source := serviceObservation(a, findings[b.Measurement])
	control := serviceObservation(c, findings[b.PositiveControl])
	result := models.NewCheckResult("audit", "service_policy", a.Runner, a.Name)
	result.Expected["policy"] = b.Policy.Name
	result.Expected["outcome"] = b.Expected
	result.Observed["from"] = b.Policy.From
	result.Observed["to"] = b.Policy.To
	result.Observed["destination"] = b.Destination.String()
	result.Observed["service"] = a.Type
	result.Observed["protocol"] = b.Protocol
	result.Observed["port"] = b.Port
	family := "ipv6"
	if b.Destination.Is4() {
		family = "ipv4"
	}
	result.Observed["ip_family"] = family
	result.Observed["source_probe"] = a.Runner
	result.Observed["positive_control_probe"] = c.Runner
	result.Observed["source_observation"] = source
	result.Observed["positive_control_observation"] = control
	if a.Type == "dns_check" {
		result.Observed["flow"] = "new_query"
	} else {
		result.Observed["flow"] = "new_connection"
	}
	result.Observed["established_reply"] = "unmeasured"
	checks := serviceFirewallChecks(spec, b.Policy.Name, findings)
	result.Observed["firewall_checks"] = checks
	if len(checks) == 0 {
		result.Observed["firewall_evidence"] = "unavailable"
	} else {
		result.Observed["firewall_evidence"] = "recorded"
	}
	result.Status = models.StatusWarn
	switch {
	case control != "reachable":
		result.Summary = "Unverified: positive control did not confirm the destination service"
	case source == "unknown":
		result.Summary = "Unverified: source probe did not produce a service measurement"
	case (source == "reachable") == (b.Expected == "allow"):
		result.Status = models.StatusPass
		result.Summary = fmt.Sprintf("Observed %s from %s, consistent with the declared %s policy", source, a.Runner, b.Expected)
	default:
		result.Status = models.StatusFail
		result.Summary = fmt.Sprintf("Observed %s from %s, contrary to the declared %s policy", source, a.Runner, b.Expected)
	}
	result.Finish()
	return *result
}

// Raw failures and DNS lookup failures can also indicate broken probe tooling
// or DNS errors. Only a measured TCP nonconnection is a negative observation.
func serviceObservation(a intent.Assertion, result models.CheckResult) string {
	if result.Runner != a.Runner || result.CheckType != a.Type {
		return "unknown"
	}
	if a.Type == "dns_check" {
		if result.Status == models.StatusPass {
			return "reachable"
		}
		return "unknown"
	}
	if result.Status != models.StatusPass && result.Status != models.StatusFail {
		return "unknown"
	}
	rows, _ := result.Observed["ports"].([]interface{})
	if len(rows) != 1 {
		return "unknown"
	}
	row, _ := rows[0].(map[string]interface{})
	switch row["state"] {
	case "open":
		return "reachable"
	case "closed":
		return "unreachable"
	}
	return "unknown"
}

type serviceFirewallCheck struct {
	Provider string        `json:"provider"`
	Expect   string        `json:"expected"`
	Status   models.Status `json:"status"`
}

func serviceFirewallChecks(spec *intent.Spec, policy string, findings []models.CheckResult) []serviceFirewallCheck {
	checks := []serviceFirewallCheck{}
	for i, a := range spec.Assertions {
		if a.Type == "acl_check" && a.Policy == policy {
			checks = append(checks, serviceFirewallCheck{Provider: findings[i].Tool, Expect: a.Expect, Status: findings[i].Status})
		}
	}
	return checks
}
