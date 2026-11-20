package topology

import (
	"slices"
)

// EndpointSet is one side of a rule resolved against the observed
// segments: specific VLANs, a wildcard ("any"), or an endpoint that maps to
// no segment (an IP group, alias, or host).
type EndpointSet struct {
	VLANs      []int
	Any        bool
	Unresolved bool
}

// ObservedRule is one enabled firewall rule or ACL with both endpoints
// resolved to segments.
type ObservedRule struct {
	Provider    string
	Allow       bool
	Source      EndpointSet
	Destination EndpointSet
}

// PairCount is one provider's rules that name a segment pair exactly.
type PairCount struct {
	Provider string `json:"provider"`
	Allow    int    `json:"allow"`
	Deny     int    `json:"deny"`
}

// MatrixPair is an ordered segment pair. PairSpecific is false when no rule
// names this exact pair; wildcard rules may still apply (see
// MatrixProviderTotals).
type MatrixPair struct {
	From         int         `json:"from_vlan"`
	To           int         `json:"to_vlan"`
	PairSpecific bool        `json:"pair_specific"`
	Rules        []PairCount `json:"rules,omitempty"`
}

// MatrixProviderTotals counts a provider's rules that the pair cells do not
// show: wildcard rules and rules with an endpoint that maps to no segment.
type MatrixProviderTotals struct {
	Provider   string `json:"provider"`
	Wildcard   int    `json:"wildcard"`
	Unresolved int    `json:"unresolved"`
}

// EnforcementMatrix is the segment x segment view of enforced rules.
type EnforcementMatrix struct {
	Pairs     []MatrixPair           `json:"pairs"`
	Providers []MatrixProviderTotals `json:"providers,omitempty"`
}

// Uncovered lists the ordered pairs that no rule names exactly.
func (m *EnforcementMatrix) Uncovered() [][2]int {
	var out [][2]int
	for _, p := range m.Pairs {
		if !p.PairSpecific {
			out = append(out, [2]int{p.From, p.To})
		}
	}
	return out
}

type pairKey struct{ from, to int }

// BuildMatrix counts, for every ordered pair of distinct observed VLANs,
// the rules that name that exact pair, per provider and action. A rule with
// an unresolved endpoint is counted as unresolved; otherwise a rule with a
// wildcard endpoint is counted as a wildcard. Neither is spread across
// pairs, so "no pair-specific rule" stays visible. Same-segment rules are
// not pairs. A rule that names a VLAN no inventory observed still counts
// toward the observed pairs it names, and is also counted as unresolved so
// it is never silently dropped.
func BuildMatrix(observedVLANs []int, rules []ObservedRule) *EnforcementMatrix {
	segments := slices.Clone(observedVLANs)
	slices.Sort(segments)
	segments = slices.Compact(segments)

	observed := make(map[int]bool, len(segments))
	for _, v := range segments {
		observed[v] = true
	}
	counts := map[pairKey]map[string]*PairCount{}
	totals := map[string]*MatrixProviderTotals{}
	total := func(provider string) *MatrixProviderTotals {
		if totals[provider] == nil {
			totals[provider] = &MatrixProviderTotals{Provider: provider}
		}
		return totals[provider]
	}
	for _, r := range rules {
		switch {
		case r.Source.Unresolved || r.Destination.Unresolved:
			total(r.Provider).Unresolved++
		case r.Source.Any || r.Destination.Any:
			total(r.Provider).Wildcard++
		default:
			if namesUnobserved := countPairs(counts, observed, r); namesUnobserved {
				total(r.Provider).Unresolved++
			}
		}
	}

	m := &EnforcementMatrix{Pairs: []MatrixPair{}}
	for _, from := range segments {
		for _, to := range segments {
			if from != to {
				m.Pairs = append(m.Pairs, matrixPair(from, to, counts[pairKey{from, to}]))
			}
		}
	}
	for _, provider := range sortedKeys(totals) {
		m.Providers = append(m.Providers, *totals[provider])
	}
	return m
}

// countPairs adds the rule to each observed pair it names and reports
// whether it also names a VLAN outside the observed segments.
func countPairs(counts map[pairKey]map[string]*PairCount, observed map[int]bool, r ObservedRule) (namesUnobserved bool) {
	for _, from := range r.Source.VLANs {
		for _, to := range r.Destination.VLANs {
			if !observed[from] || !observed[to] {
				namesUnobserved = true
				continue
			}
			if from == to {
				continue
			}
			key := pairKey{from, to}
			if counts[key] == nil {
				counts[key] = map[string]*PairCount{}
			}
			c := counts[key][r.Provider]
			if c == nil {
				c = &PairCount{Provider: r.Provider}
				counts[key][r.Provider] = c
			}
			if r.Allow {
				c.Allow++
			} else {
				c.Deny++
			}
		}
	}
	return namesUnobserved
}

func matrixPair(from, to int, byProvider map[string]*PairCount) MatrixPair {
	pair := MatrixPair{From: from, To: to, PairSpecific: len(byProvider) > 0}
	for _, provider := range sortedKeys(byProvider) {
		pair.Rules = append(pair.Rules, *byProvider[provider])
	}
	return pair
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
