package topology

import (
	"cmp"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"
)

// ResourceRef identifies a resource in one connection. A port key includes its
// parent device. Controller-provided keys and names are private.
type ResourceRef struct{ Kind, Key string }

type Observation struct {
	Ref                              ResourceRef
	Name, MAC, GatewayPrefix, Device string
	VLAN, Port                       int
	STPDiscarding                    *bool
}

// MapTarget selects a local resource by ID or tag, a peer by chassis MAC, or
// an addressed gateway by tag AND exact gateway prefix. Only the latter two
// selectors may span explicitly grouped connections.
type MapTarget struct {
	Ref                                 ResourceRef
	MAC, GatewayPrefix, AddressedDevice string
	VLAN                                int
}

type LinkObservation struct {
	From               ResourceRef
	To                 MapTarget
	Relation, Evidence string // adapter-defined categories, never raw controller strings
	Inferred           bool
}

type ObservationSet struct {
	ControllerSite string // resolved private site name, if reported by the adapter
	Resources      []Observation
	Links          []LinkObservation
	Gaps           []string   // adapter-defined collection names, never API error messages
	ObservedAt     *time.Time // source time, nil when the API does not report freshness
}

type MapInput struct {
	Provider, Profile, Site, LogicalSite string
	Facts                                ObservationSet
}

type MapSource struct {
	ID             string     `json:"id"`
	Provider       string     `json:"provider"`
	Site           string     `json:"site"`
	Profile        string     `json:"profile,omitempty"`
	ControllerSite string     `json:"controller_site,omitempty"`
	LogicalSite    string     `json:"logical_site,omitempty"`
	ObservedAt     *time.Time `json:"observed_at"`
	Gaps           []string   `json:"gaps,omitempty"`
}
type MapResource struct {
	ID            string `json:"id"`
	Source        string `json:"source"`
	Kind          string `json:"kind"`
	VLAN          int    `json:"vlan,omitempty"`
	Port          int    `json:"port,omitempty"`
	STPDiscarding *bool  `json:"stp_discarding,omitempty"`
	NativeID      string `json:"native_id,omitempty"`
	Name          string `json:"name,omitempty"`
	MAC           string `json:"mac,omitempty"`
	GatewayPrefix string `json:"gateway_prefix,omitempty"`
}
type MapLink struct {
	From     string   `json:"from"`
	Targets  []string `json:"targets"`
	Relation string   `json:"relation"`
	Evidence string   `json:"evidence"`
	State    string   `json:"state"`
}
type NetworkMap struct {
	Sources   []MapSource   `json:"sources"`
	Resources []MapResource `json:"resources"`
	Links     []MapLink     `json:"links"`
}

// mapKey scopes lookups to the source connection or to an operator-declared
// logical site. Separate namespaces keep an adapter key from matching a MAC.
type mapKey struct {
	scope, namespace, kind, value string
	vlan                          int
}

// Only locally administered or globally unique unicast chassis addresses identify a peer.
func chassisMAC(value string) (string, bool) {
	mac, err := net.ParseMAC(value)
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 || slices.Equal(mac, []byte{0, 0, 0, 0, 0, 0}) {
		return "", false
	}
	return mac.String(), true
}

func (target MapTarget) lookup(source MapSource) (mapKey, bool) {
	switch {
	case target.Ref.Kind != "":
		return mapKey{scope: source.ID, namespace: "local", kind: target.Ref.Kind, value: target.Ref.Key}, target.Ref.Key != ""
	case target.AddressedDevice != "":
		return mapKey{scope: source.ID, namespace: "addressed interface", value: target.AddressedDevice}, true
	case target.MAC != "":
		mac, ok := chassisMAC(target.MAC)
		return mapKey{scope: source.Site, namespace: "mac", value: mac}, ok
	case target.GatewayPrefix != "":
		p, err := netip.ParsePrefix(target.GatewayPrefix)
		return mapKey{scope: source.Site, namespace: "gateway", value: p.String(), vlan: target.VLAN}, err == nil && !p.Addr().IsUnspecified() && p.Bits() > 0 && target.VLAN > 0
	case target.VLAN > 0:
		return mapKey{scope: source.ID, namespace: "tag", vlan: target.VLAN}, true
	default:
		return mapKey{}, false
	}
}

type mapIndex map[mapKey][]string

func (index mapIndex) add(source MapSource, row Observation, id string) {
	targets := []MapTarget{{Ref: row.Ref}, {MAC: row.MAC}}
	if row.GatewayPrefix != "" && (row.Ref.Kind == "gateway" || row.Ref.Kind == "interface") {
		targets = append(targets, MapTarget{GatewayPrefix: row.GatewayPrefix, VLAN: row.VLAN}, MapTarget{AddressedDevice: row.Device})
	}
	if row.Ref.Kind == "segment" {
		targets = append(targets, MapTarget{VLAN: row.VLAN})
	}
	for _, target := range targets {
		if k, ok := target.lookup(source); ok {
			index[k] = append(index[k], id)
		}
	}
}

func (index mapIndex) match(source MapSource, link LinkObservation) (MapLink, bool) {
	from, ok := (MapTarget{Ref: link.From}).lookup(source)
	if !ok || len(index[from]) != 1 {
		return MapLink{}, false
	}
	to, ok := link.To.lookup(source)
	targets := []string{}
	if ok {
		targets = append(targets, index[to]...)
	}
	state := "observed"
	switch {
	case len(targets) == 0:
		state = "missing"
	case len(targets) > 1:
		state = "ambiguous"
	case link.Inferred:
		state = "inferred"
	}
	return MapLink{From: index[from][0], Targets: targets, Relation: link.Relation, Evidence: link.Evidence, State: state}, true
}

func (m *NetworkMap) addSource(in MapInput, sites map[string]string, detail bool) *MapSource {
	n := len(m.Sources) + 1
	source := MapSource{ID: fmt.Sprintf("c%d", n), Provider: in.Provider, Site: fmt.Sprintf("s%d", n), ObservedAt: in.Facts.ObservedAt, Gaps: slices.Clone(in.Facts.Gaps)}
	if in.LogicalSite != "" {
		if site, ok := sites[in.LogicalSite]; ok {
			source.Site = site
		} else {
			sites[in.LogicalSite] = source.Site
		}
	}
	if detail {
		source.Profile = in.Profile
		source.ControllerSite = in.Facts.ControllerSite
		if source.ControllerSite == "" {
			source.ControllerSite = in.Site
		}
		source.LogicalSite = in.LogicalSite
	}
	m.Sources = append(m.Sources, source)
	return &m.Sources[len(m.Sources)-1]
}

func (m *NetworkMap) indexResources(source *MapSource, observations []Observation, index mapIndex, detail bool) {
	rows := slices.Clone(observations)
	slices.SortStableFunc(rows, func(a, b Observation) int {
		return cmp.Or(strings.Compare(a.Ref.Kind, b.Ref.Kind), strings.Compare(a.Ref.Key, b.Ref.Key))
	})
	for _, r := range rows {
		if r.Ref.Key == "" || r.Ref.Kind == "" {
			source.Gaps = append(source.Gaps, "resource identity")
			continue
		}
		row := MapResource{ID: fmt.Sprintf("r%d", len(m.Resources)+1), Source: source.ID, Kind: r.Ref.Kind, Port: r.Port, VLAN: r.VLAN, STPDiscarding: r.STPDiscarding}
		if detail {
			row.NativeID = r.Ref.Key
			row.Name = r.Name
			row.MAC = r.MAC
			row.GatewayPrefix = r.GatewayPrefix
		}
		m.Resources = append(m.Resources, row)
		index.add(*source, r, row.ID)
	}
}

// BuildNetworkMap assigns report-local opaque handles before resolving links.
// Default output omits native resource identifiers, labels and addresses.
func BuildNetworkMap(inputs []MapInput, detail bool) NetworkMap {
	m := NetworkMap{Sources: []MapSource{}, Resources: []MapResource{}, Links: []MapLink{}}
	sites := map[string]string{}
	index := mapIndex{}
	for _, in := range inputs {
		source := m.addSource(in, sites, detail)
		m.indexResources(source, in.Facts.Resources, index, detail)
	}
	for i, in := range inputs {
		source := &m.Sources[i]
		for _, l := range in.Facts.Links {
			link, ok := index.match(*source, l)
			if !ok {
				source.Gaps = append(source.Gaps, "link source identity")
				continue
			}
			m.Links = append(m.Links, link)
		}
		slices.Sort(source.Gaps)
		source.Gaps = slices.Compact(source.Gaps)
	}
	slices.SortStableFunc(m.Links, func(a, b MapLink) int {
		return cmp.Or(strings.Compare(a.From, b.From), strings.Compare(a.Relation, b.Relation), strings.Compare(a.Evidence, b.Evidence), slices.Compare(a.Targets, b.Targets))
	})
	return m
}
