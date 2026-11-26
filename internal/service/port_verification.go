package service

import (
	"context"
	"net"
	"strconv"
	"strings"

	backend "github.com/jpvelasco/nyx/internal/backends/omada"
)

// PortVerification records post-apply evidence available from the controller.
// Connectivity describes the current managed attachment, not a traffic test.
type PortVerification struct {
	Membership   string `json:"membership"`
	Connectivity string `json:"connectivity"`
	DHCP         string `json:"dhcp"`
}

func verifyPortEvidence(ctx context.Context, c *backend.Client, site string, req OmadaPortProfileRequest, ports []backend.SwitchPort, profiles []backend.LanProfile, nets []backend.Network) *PortVerification {
	result := &PortVerification{Membership: "unverified", Connectivity: "unverified", DHCP: "unverified"}
	req.ExpectedRevision = ""
	plan, _, _, err := planPortFromState(site, req, ports, profiles, nets)
	if err == nil && plan.Current != nil && !plan.Current.ProfileOverride {
		if plan.Outcome == "unchanged" && strings.EqualFold(plan.Current.NativeNetwork, plan.CurrentProfile.NativeNetwork) {
			result.Membership = "observed"
		} else {
			result.Membership = "mismatch"
		}
	}
	mac, err := net.ParseMAC(req.VerifyClientMAC)
	if err != nil || len(mac) != 6 {
		return result
	}
	nodes, err := c.GetClientTopology(ctx, site, mac.String())
	if err == nil {
		for _, n := range nodes {
			if n.NodeType != "clientNode" || backend.NormalizeMAC(n.MAC) != backend.NormalizeMAC(mac.String()) || n.SwitchPort == "" {
				continue
			}
			if backend.NormalizeMAC(n.SwitchMAC) == backend.NormalizeMAC(req.SwitchMAC) && n.SwitchPort == strconv.Itoa(req.Port) {
				result.Connectivity = "attached"
			} else {
				result.Connectivity = "different attachment"
			}
		}
	}
	rows := []backend.ConnectedClient{{MAC: mac.String()}}
	if err := c.EnrichFromDHCP(ctx, site, rows, nets); err == nil && rows[0].IP != "" {
		if strings.EqualFold(rows[0].NetworkName, req.Native) {
			result.DHCP = "lease on desired native network"
		} else if rows[0].NetworkName != "" {
			result.DHCP = "lease on another network"
		} else {
			result.DHCP = "lease network unknown"
		}
	}
	return result
}
