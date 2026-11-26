package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strconv"

	backend "github.com/jpvelasco/nyx/internal/backends/omada"
)

// portRevision binds the preview to its selected site, switch, port and effective
// configuration. It contains no credentials and is recomputed before a bind.
func portRevision(siteID string, port *OmadaSwitchPort, profile *OmadaLanProfile, native string, tags []string) (string, error) {
	ordered := slices.Clone(tags)
	slices.Sort(ordered)
	raw, err := json.Marshal(struct {
		Site    string
		Port    *OmadaSwitchPort
		Profile *OmadaLanProfile
		Native  string
		Tagged  []string
	}{siteID, port, profile, native, ordered})
	if err != nil {
		return "", err
	}
	return digestPortState(raw), nil
}

func digestPortState(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

const roleRevisionPrefix = "role-v1-"

// portAttachments captures the identities used in the switch impact decision.
// Its digest excludes labels, traffic counters and unrelated switch ports.
type portAttachments struct{ Clients, APs, Neighbors []string }

func (a portAttachments) revision(config string) (string, error) {
	slices.Sort(a.Clients)
	slices.Sort(a.APs)
	slices.Sort(a.Neighbors)
	raw, err := json.Marshal(struct {
		Config      string
		Attachments portAttachments
	}{config, a})
	if err != nil {
		return "", err
	}
	return roleRevisionPrefix + digestPortState(raw), nil
}
func readPortAttachments(ctx context.Context, c *backend.Client, site, sw string) (map[int]*portAttachments, error) {
	mac := backend.NormalizeMAC(sw)
	rows := map[int]*portAttachments{}
	at := func(port int) *portAttachments {
		r := rows[port]
		if r == nil {
			r = &portAttachments{}
			rows[port] = r
		}
		return r
	}
	clients, known := switchClients(ctx, c, site, mac)
	if !known {
		return nil, errors.New("switch client inventory unavailable")
	}
	for port, list := range clients {
		at(port).Clients = list
	}
	neighbors, err := c.GetLLDPNeighbors(ctx, site, sw)
	if err != nil {
		return nil, err
	}
	for _, n := range neighbors {
		r := at(n.Port)
		r.Neighbors = append(r.Neighbors, backend.NormalizeMAC(n.Chassis))
	}
	devices, err := c.GetDevices(ctx, site)
	if err != nil {
		return nil, err
	}
	var aps []string
	for _, d := range devices {
		if d.IsAP() {
			aps = append(aps, d.MAC)
		}
	}
	if len(aps) > 0 {
		edges, err := c.GetUplinkInfo(ctx, site, aps)
		if err != nil {
			return nil, err
		}
		for _, e := range edges {
			if backend.NormalizeMAC(e.UplinkDeviceMAC) != mac {
				continue
			}
			port, err := strconv.Atoi(e.UplinkDevicePort)
			if err != nil || port <= 0 {
				return nil, errors.New("AP uplink port unavailable")
			}
			r := at(port)
			r.APs = append(r.APs, backend.NormalizeMAC(e.MAC))
		}
	}
	return rows, nil
}
func (a portAttachments) matches(role, client string, downstream []string) bool {
	switch role {
	case "access":
		return len(a.Clients) == 1 && a.Clients[0] == backend.NormalizeMAC(client) && len(a.APs) == 0 && len(a.Neighbors) == 0
	case "ap-uplink":
		if len(downstream) != 1 || len(a.APs) != 1 || downstream[0] != a.APs[0] || len(a.Clients) != 0 {
			return false
		}
		return !slices.ContainsFunc(a.Neighbors, func(n string) bool { return n != a.APs[0] })
	default:
		return false
	}
}
