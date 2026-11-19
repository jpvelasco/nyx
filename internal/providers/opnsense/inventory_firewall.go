package opnsense

import "strings"

// InventoryRule is a filter grid row with configured members of referenced aliases.
type InventoryRule struct {
	FirewallRule
	Active       bool                `json:"active"`
	AliasMembers map[string][]string `json:"configured_alias_members,omitempty"`
}

// FirewallInventory exposes the rules and aliases observed independently.
type FirewallInventory struct {
	Rules     []InventoryRule  `json:"firewall_rules"`
	Aliases   []InventoryAlias `json:"firewall_aliases"`
	AliasesOK bool             `json:"firewall_aliases_ok"`
}

// InventoryAlias preserves configured members even for disabled aliases.
type InventoryAlias struct {
	Alias
	Members  []string `json:"configured_members"`
	Disabled bool     `json:"disabled"`
}

// FirewallInventory uses configured members directly, including nested alias
// names and other dynamic inputs. It does not query or approximate live tables.
func (snap *InventorySnapshot) FirewallInventory() FirewallInventory {
	inv := FirewallInventory{AliasesOK: snap.AliasesOK}
	aliases := make(map[string]Alias, len(snap.Aliases))
	if snap.AliasesOK {
		inv.Aliases = make([]InventoryAlias, 0, len(snap.Aliases))
	}
	for _, alias := range snap.Aliases {
		aliases[alias.Name] = alias
		inv.Aliases = append(inv.Aliases, InventoryAlias{Alias: alias, Members: alias.Addresses, Disabled: alias.Disabled})
	}
	if snap.RulesOK {
		inv.Rules = make([]InventoryRule, 0, len(snap.Rules))
	}
	for _, rule := range snap.Rules {
		row := InventoryRule{FirewallRule: rule, Active: !rule.Disabled}
		for _, field := range []string{rule.Source, rule.Destination, rule.SourcePort, rule.DestPort} {
			for _, token := range splitCSV(field) {
				alias, found := aliases[strings.TrimSpace(strings.TrimPrefix(token, "!"))]
				if !found || alias.Disabled {
					continue
				}
				if row.AliasMembers == nil {
					row.AliasMembers = make(map[string][]string)
				}
				row.AliasMembers[alias.Name] = alias.Addresses
			}
		}
		inv.Rules = append(inv.Rules, row)
	}
	return inv
}
