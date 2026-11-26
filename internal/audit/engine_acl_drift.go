package audit

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/providers"
)

// Older specs can already identify their controller through acl_check. Keep the
// declared assertion positions intact and append one inventory check per provider.
func withACLDrift(assertions []intent.Assertion) []intent.Assertion {
	included := map[string]bool{}
	for _, a := range assertions {
		if a.Type == "acl_drift" {
			included[a.Provider] = true
		}
	}
	result := slices.Clone(assertions)
	for _, a := range assertions {
		if a.Type == "acl_check" && !included[a.Provider] && (a.Provider == "omada" || a.Provider == "opnsense") {
			result = append(result, intent.Assertion{Type: "acl_drift", Provider: a.Provider})
			included[a.Provider] = true
		}
	}
	return result
}

func (e *Engine) runACLDrift(ctx context.Context, provider string) (*models.CheckResult, error) {
	adapter, _ := providers.LookupAdapter(provider)
	observer, ok := adapter.(providers.ACLObserver)
	opts := e.controllerOptions(provider)
	var observation providers.ACLObservation
	var unavailable string
	switch {
	case !ok:
		unavailable = "provider does not support ACL observation"
	case opts.Connection.Require(opts.Credentials) != nil:
		unavailable = "provider credentials are missing"
	default:
		var err error
		observation, err = observer.ObserveACLs(ctx, opts, e.Spec.Networks)
		if err != nil {
			unavailable = "could not read controller rule inventory"
		}
	}
	if unavailable != "" {
		r := models.NewCheckResult(provider, "acl_drift", provider, provider)
		r.Status = models.StatusWarn
		r.Summary = "ACL inventory unknown: " + unavailable
		r.Finish()
		return r, nil
	}
	// Explicit scope or existing acl_check associates a declaration with a
	// controller. Unqualified policies are compared to the selected inventory.
	var policies []intent.Policy
	for _, p := range e.Spec.Policies {
		if p.Scope != "" && (p.Scope == "filter") != (provider == "opnsense") {
			continue
		}
		providerUnspecified, owned := true, false
		for _, a := range e.Spec.Assertions {
			if a.Type == "acl_check" && a.Policy == p.Name {
				providerUnspecified = false
				owned = owned || a.Provider == provider
			}
		}
		if owned || providerUnspecified {
			policies = append(policies, p)
		}
	}
	return compareACLs(provider, policies, observation), nil
}

func compareACLs(provider string, policies []intent.Policy, live providers.ACLObservation) *models.CheckResult {
	result := models.NewCheckResult(provider, "acl_drift", provider, provider)
	var absent, extra []string
	matched := make([]bool, len(live.Rules))
	unknown := slices.Clone(live.UnknownScopes)
	for _, r := range live.Rules {
		if r.Name == "" {
			unknown = append(unknown, r.Scope)
		}
	}
	for _, policy := range policies {
		present := false
		for i, rule := range live.Rules {
			if strings.EqualFold(policy.Name, rule.Name) && (policy.Scope == "" || policy.Scope == rule.Scope) {
				present = true
				matched[i] = true
			}
		}
		if present || slices.Contains(unknown, policy.Scope) || (policy.Scope == "" && len(unknown) > 0) {
			continue
		}
		name := policy.Name
		if policy.Scope != "" {
			name = policy.Scope + "/" + name
		}
		absent = append(absent, name)
	}
	for i, r := range live.Rules {
		if !matched[i] && r.Name != "" {
			extra = append(extra, r.Scope+"/"+r.Name)
		}
	}
	slices.Sort(absent)
	slices.Sort(extra)
	slices.Sort(unknown)
	unknown = slices.Compact(unknown)
	result.Observed["declared_but_absent"] = absent
	result.Observed["live_but_undeclared"] = extra
	result.Observed["unknown_scopes"] = unknown
	result.Status = models.StatusPass
	if len(extra) > 0 || len(unknown) > 0 {
		result.Status = models.StatusWarn
	}
	if len(absent) > 0 {
		result.Status = models.StatusFail
	}
	result.Summary = fmt.Sprintf("ACL inventory: %d declared but absent, %d live but undeclared", len(absent), len(extra))
	if len(unknown) > 0 {
		result.Summary += ". Incomplete inventory for " + strings.Join(unknown, ", ")
	}
	for _, name := range absent {
		result.Violations = append(result.Violations, "declared but absent: "+strconv.Quote(name))
	}

	result.Finish()
	return result
}

// The drift pass consumes gateway measurements already made by isolation
// assertions. A timed-out command, an unbound vantage or an absent check
// supplies no observation. A silent gateway does not identify the blocking rule.
func uncoveredDirections(spec *intent.Spec, findings []models.CheckResult) []string {
	var uncovered []string
	for i, a := range spec.Assertions {
		if a.Type != "isolation" {
			continue
		}
		blocked, _ := findings[i].Observed["unreachable_gateways"].([]string)
		source, _ := findings[i].Observed["source_network"].(string)
		if source == "" {
			continue
		}
		for _, n := range spec.Networks {
			if !slices.Contains(blocked, n.Gateway) || !spec.EndpointCovers(a.To, n.Name) {
				continue
			}
			covered := slices.ContainsFunc(spec.Policies, func(p intent.Policy) bool {
				return spec.EndpointCovers(p.From, source) && spec.EndpointCovers(p.To, n.Name)
			})
			if !covered {
				uncovered = append(uncovered, source+" -> "+n.Name)
			}
		}
	}
	slices.Sort(uncovered)
	return slices.Compact(uncovered)
}
