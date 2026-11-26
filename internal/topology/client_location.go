package topology

import (
	"cmp"
	"slices"
	"strings"
)

// ClientObservation is evidence about a single, explicitly selected MAC.
// Current associations and historical or cached layer-three evidence have
// different meanings even when they describe the same client.
type ClientObservation struct {
	Kind                  string      // association, history, DHCP lease, ARP, NDP
	Status                string      // current, historical, cached, expired or unknown
	Attachment            ResourceRef // nearest observed managed AP or switch port
	Address, Device, SSID string      // private
	VLAN, Port            int
	LastSeen              int64 // controller-reported value, units as documented by the adapter
}

type ClientEvidence struct {
	Source     string `json:"source"`
	Kind       string `json:"kind"`
	Status     string `json:"status"`
	Attachment string `json:"attachment,omitempty"`
	VLAN       int    `json:"vlan,omitempty"`
	Port       int    `json:"port,omitempty"`
	LastSeen   int64  `json:"controller_last_seen,omitempty"`
	Address    string `json:"address,omitempty"`
	Device     string `json:"device,omitempty"`
	SSID       string `json:"ssid,omitempty"`
}

type ClientLocation struct {
	Status         string           `json:"status"`
	DownstreamPort string           `json:"downstream_port"`
	Evidence       []ClientEvidence `json:"evidence"`
	Path           NetworkMap       `json:"path"`
}

type attachmentKey struct{ source, kind, native string }

// LocateClient traces configured topology from current managed attachments.
// A managed port identifies the last visible uplink. An unmanaged downstream
// port has no observable identity in a controller's inventory.
type ClientMapInput struct {
	MapInput
	Evidence []ClientObservation
}

func LocateClient(sources []ClientMapInput, detail bool) ClientLocation {
	inputs := make([]MapInput, 0, len(sources))
	for _, source := range sources {
		inputs = append(inputs, source.MapInput)
	}
	full := BuildNetworkMap(inputs, true)
	output := BuildNetworkMap(inputs, detail)
	index := map[attachmentKey][]string{}
	for _, r := range full.Resources {
		k := attachmentKey{r.Source, r.Kind, r.NativeID}
		index[k] = append(index[k], r.ID)
	}
	result := ClientLocation{Status: "unconfirmed", DownstreamPort: "unknown", Evidence: []ClientEvidence{}, Path: NetworkMap{Sources: output.Sources, Resources: []MapResource{}, Links: []MapLink{}}}
	current := map[string]bool{}
	wired := map[string]bool{}
	ambiguous := false
	for i, source := range sources {
		for _, row := range source.Evidence {
			c := ClientEvidence{Source: output.Sources[i].ID, Kind: row.Kind, Status: row.Status, Port: row.Port, VLAN: row.VLAN, LastSeen: row.LastSeen}
			if detail {
				c.Address = row.Address
				c.Device = row.Device
				c.SSID = row.SSID
			}
			candidates := index[attachmentKey{c.Source, row.Attachment.Kind, row.Attachment.Key}]
			if len(candidates) == 1 {
				c.Attachment = candidates[0]
			}
			if row.Kind == "association" && row.Status == "current" {
				if c.Attachment != "" {
					current[c.Attachment] = true
					if row.Attachment.Kind == "port" {
						wired[c.Attachment] = true
					}
				} else {
					ambiguous = ambiguous || len(candidates) > 1
				}
			}
			result.Evidence = append(result.Evidence, c)
		}
	}
	switch {
	case ambiguous || len(current) > 1:
		result.Status = "ambiguous"
	case len(current) == 1:
		result.Status = "located"
	}
	result.Path = attachmentPath(output, current, wired)
	slices.SortStableFunc(result.Evidence, func(a, b ClientEvidence) int {
		return cmp.Or(strings.Compare(a.Source, b.Source), strings.Compare(a.Kind, b.Kind), strings.Compare(a.Attachment, b.Attachment), cmp.Compare(b.LastSeen, a.LastSeen))
	})
	return result
}

// attachmentPath follows one managed association to its visible network. A
// wireless client's uplink never derives its client VLAN from the AP's native
// VLAN; that is the AP management path and may differ from the broadcast SSID.
func attachmentPath(m NetworkMap, starts, wired map[string]bool) NetworkMap {
	path := NetworkMap{Sources: m.Sources, Resources: []MapResource{}, Links: []MapLink{}}
	bySource := map[string][]MapLink{}
	for _, l := range m.Links {
		if l.State != "observed" && l.State != "inferred" {
			continue
		}
		switch l.Relation {
		case "native":
			if !wired[l.From] {
				continue
			}
		case "uplink", "device", "gateway":
		default:
			continue
		}
		bySource[l.From] = append(bySource[l.From], l)
	}
	seen := map[string]bool{}
	var queue []string
	for id := range starts {
		seen[id] = true
		queue = append(queue, id)
	}
	slices.Sort(queue)
	for pos := 0; pos < len(queue); pos++ {
		for _, l := range bySource[queue[pos]] {
			path.Links = append(path.Links, l)
			for _, id := range l.Targets {
				if !seen[id] {
					seen[id] = true
					queue = append(queue, id)
				}
			}
		}
	}
	for _, r := range m.Resources {
		if seen[r.ID] {
			path.Resources = append(path.Resources, r)
		}
	}
	return path
}
