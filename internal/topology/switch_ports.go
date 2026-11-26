package topology

import (
	"errors"
	"slices"
)

// PortIntent supplies the operator's role and desired VLAN membership. An
// access-port change also identifies the client expected at that attachment.
type PortIntent struct {
	Port      int      `json:"port"`
	Role      string   `json:"role"`
	Native    string   `json:"native"`
	Tagged    []string `json:"tagged,omitempty"`
	ClientMAC string   `json:"client_mac,omitempty"`
}

type SwitchPortPolicy struct {
	ManagementVLAN int          `json:"management_vlan"`
	Ports          []PortIntent `json:"ports"`
}

type PortImpact struct {
	Port       int      `json:"port"`
	Role       string   `json:"role"`
	Eligible   bool     `json:"eligible"`
	Reason     string   `json:"reason"`
	Downstream []string `json:"downstream"`
}

// EvaluateSwitchPort compares one port's role with the topology evidence.
// Evidence handles are opaque within the network map used for the plan.
func EvaluateSwitchPort(m NetworkMap, portID string, intent PortIntent, managementVLAN int, clientLocated bool) PortImpact {
	result := PortImpact{Port: intent.Port, Role: "ambiguous", Reason: "port is missing from the switch inventory", Downstream: []string{}}
	byID := map[string]MapResource{}
	for _, r := range m.Resources {
		byID[r.ID] = r
	}
	p, ok := byID[portID]
	if !ok || p.Kind != "port" {
		return result
	}
	var native MapResource
	peers := map[string]string{}
	unknownNeighbor := false
	tagged := []string{}
	unknownTags := false
	for _, l := range m.Links {
		switch {
		case l.From == portID && l.Relation == "native" && l.State == "observed" && len(l.Targets) == 1:
			native = byID[l.Targets[0]]
		case l.From == portID && l.Relation == "tagged":
			if len(l.Targets) != 1 || l.State != "observed" || byID[l.Targets[0]].Name == "" {
				unknownTags = true
			} else {
				tagged = append(tagged, byID[l.Targets[0]].Name)
			}
		case l.From == portID && l.Relation == "neighbor":
			if l.State != "observed" || len(l.Targets) != 1 {
				unknownNeighbor = true
				continue
			}
			for _, id := range l.Targets {
				peers[id] = byID[id].Kind
			}
		case l.Relation == "uplink" && l.State == "observed" && slices.Contains(l.Targets, portID):
			peers[l.From] = byID[l.From].Kind
		}
	}
	for id := range peers {
		result.Downstream = append(result.Downstream, id)
	}
	slices.Sort(result.Downstream)
	if native.Kind == "" || native.VLAN == 0 {
		result.Reason = "native VLAN is unknown"
		return result
	}
	if unknownNeighbor || len(peers) > 1 {
		result.Reason = "shared or unresolved neighbor evidence"
		return result
	}
	if p.STPDiscarding != nil && *p.STPDiscarding {
		result.Reason = "spanning tree reports a discarding port"
		return result
	}
	result.Role = "access"
	for _, kind := range peers {
		switch kind {
		case "ap":
			result.Role = "ap-uplink"
		case "switch":
			result.Role = "trunk"
		case "gateway", "interface":
			result.Role = "management"
		default:
			result.Role = "ambiguous"
		}
	}
	if native.VLAN == managementVLAN && result.Role != "ap-uplink" {
		result.Role = "management"
	}
	if result.Role == "management" || result.Role == "trunk" || result.Role == "ambiguous" {
		result.Reason = "infrastructure or management reachability depends on this port"
		return result
	}
	if unknownTags || (result.Role == "access" && len(tagged) > 0) {
		result.Role = "ambiguous"
		result.Reason = "existing tagged membership may serve downstream devices"
		return result
	}
	if result.Role != intent.Role {
		result.Reason = "observed role differs from operator intent"
		return result
	}
	if result.Role == "access" && (!clientLocated || len(intent.Tagged) != 0) {
		result.Reason = "access changes require a matched client attachment and untagged membership"
		return result
	}
	if result.Role == "ap-uplink" && native.Name != intent.Native {
		result.Reason = "changing this native VLAN could disconnect the AP management interface"
		return result
	}
	if result.Role == "ap-uplink" && slices.ContainsFunc(tagged, func(name string) bool { return !slices.Contains(intent.Tagged, name) }) {
		result.Reason = "removing an observed AP VLAN could disconnect wireless clients"
		return result
	}
	result.Eligible = true
	result.Reason = "observed attachment matches the requested role"
	return result
}

func (p SwitchPortPolicy) Validate() error {
	if p.ManagementVLAN < 1 || p.ManagementVLAN > 4094 {
		return errors.New("management_vlan must be in the range 1 to 4094")
	}
	if len(p.Ports) == 0 {
		return errors.New("at least one port intent is required")
	}
	seen := map[int]bool{}
	for _, r := range p.Ports {
		if r.Port < 1 || seen[r.Port] || r.Native == "" {
			return errors.New("each port needs a unique positive number and native network")
		}
		seen[r.Port] = true
		switch r.Role {
		case "access", "ap-uplink", "trunk", "management":
		default:
			return errors.New("unknown port role")
		}
	}
	return nil
}
