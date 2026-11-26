package service

import (
	"context"
	"errors"
	"net"
	"strings"

	backend "github.com/jpvelasco/nyx/internal/backends/omada"
	"github.com/jpvelasco/nyx/internal/credentials"
	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/storepath"
	"github.com/jpvelasco/nyx/internal/topology"
)

const SwitchPortsCommand = "plan-switch"
const SwitchPortsTool = "switch_port_plan"

type PortProposal struct {
	topology.PortImpact
	Desired  *OmadaPortProfileRequest `json:"desired,omitempty"`
	Revision string                   `json:"revision,omitempty"`
	Outcome  string                   `json:"outcome,omitempty"`
}

type SwitchPortPlan struct {
	Ports   []PortProposal       `json:"ports"`
	Sources []topology.MapSource `json:"sources"`
}

// PlanSwitchPorts compares explicit intent with the selected Omada switch.
// Rows without sufficiently specific physical evidence have no proposal.
func (s *TopologyService) PlanSwitchPorts(ctx context.Context, opts NetworkMapOptions, selector, switchMAC string, policy topology.SwitchPortPolicy) (SwitchPortPlan, error) {
	if err := policy.Validate(); err != nil {
		return SwitchPortPlan{}, err
	}
	name, profile, _ := strings.Cut(selector, "/")
	if name != "omada" || profile == "" {
		return SwitchPortPlan{}, errors.New("select an Omada provider/profile for the switch")
	}
	mac, err := net.ParseMAC(switchMAC)
	if err != nil || len(mac) != 6 {
		return SwitchPortPlan{}, errors.New("invalid switch MAC")
	}
	if len(opts.Connections) != 0 && (len(opts.Connections) != 1 || opts.Connections[0] != selector) {
		return SwitchPortPlan{}, errors.New("port plan must select exactly the connection named for the switch")
	}
	opts.Connections = []string{selector}
	// Private labels are used internally to verify this switch and the AP's
	// management network. Only the requested membership is disclosable by default.
	opts.Detail = true
	m, err := s.Map(ctx, opts)
	if err != nil {
		return SwitchPortPlan{}, err
	}
	result := SwitchPortPlan{Ports: []PortProposal{}, Sources: m.Sources}
	for i := range result.Sources {
		result.Sources[i].Profile = ""
		result.Sources[i].ControllerSite = ""
		result.Sources[i].LogicalSite = ""
	}
	conn := credentials.Connection{Provider: name, Profile: profile}
	fields := credentials.Resolve(conn, nil, nil, storepath.StoreFile(), true)
	if conn.Require(fields) != nil {
		return result, errors.New("switch connection is missing credentials")
	}
	o := providers.ConnectionOptions(conn, fields)
	controller := OmadaOptions{Host: o.Host, ClientID: o.ClientID, ClientSecret: o.ClientSecret, Site: o.Site, CACertPath: opts.CACertPath, SkipTLSVerify: opts.SkipTLSVerify}
	client, site, err := s.Omada.session(ctx, controller)
	if err != nil {
		return result, errors.New("unable to read the selected switch connection")
	}
	defer client.Logout(ctx)
	attachments, attachmentErr := readPortAttachments(ctx, client, site.EffectiveID(), switchMAC)

	ids := map[int]string{}
	nativeIDs := map[string]string{}
	for _, r := range m.Resources {
		nativeIDs[r.ID] = r.NativeID
		if r.Kind == "port" && strings.HasPrefix(r.NativeID, backend.NormalizeMAC(switchMAC)+"/") {
			if _, seen := ids[r.Port]; seen {
				ids[r.Port] = ""
			} else {
				ids[r.Port] = r.ID
			}
		}
	}
	for _, intent := range policy.Ports {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		portID := ids[intent.Port]
		attached := attachments[intent.Port]
		if attached == nil {
			attached = &portAttachments{}
		}
		matched := attachmentErr == nil && attached.matches("access", intent.ClientMAC, nil)

		impact := topology.EvaluateSwitchPort(m, portID, intent, policy.ManagementVLAN, matched)
		row := PortProposal{PortImpact: impact}
		if row.Role == "access" && (len(attached.Clients) > 1 || attachmentErr != nil) {
			row.Role = "ambiguous"
			row.Eligible = false
			row.Reason = "shared or unresolved client attachment"
		}

		if impact.Eligible && unknownSwitchContext(m.Sources[0].Gaps) {
			row.Eligible = false
			row.Reason = "switch collections are incomplete"
		}
		if row.Eligible {
			request := OmadaPortProfileRequest{SwitchMAC: switchMAC, Port: intent.Port, Native: intent.Native, Tagged: intent.Tagged}
			planned, err := s.Omada.PlanPort(ctx, controller, request)
			if err != nil || planned.Current == nil || planned.CurrentProfile == nil || planned.Current.ProfileOverride || planned.Current.Disabled || (planned.Current.STPDiscarding != nil && *planned.Current.STPDiscarding) {
				row.Eligible = false
				row.Reason = "effective port configuration cannot be verified"
			} else {
				var downstream []string
				for _, id := range impact.Downstream {
					downstream = append(downstream, nativeIDs[id])
				}
				guard, err := attached.revision(planned.Revision)
				if err != nil || attachmentErr != nil || !attached.matches(intent.Role, intent.ClientMAC, downstream) {
					row.Eligible = false
					row.Reason = "current port attachments cannot be verified"
					result.Ports = append(result.Ports, row)
					continue
				}
				request.ExpectedRevision = guard
				request.SwitchMAC = ""
				row.Desired = &request
				row.Revision = guard
				row.Outcome = planned.Outcome
			}
		}
		result.Ports = append(result.Ports, row)
	}
	return result, nil
}

func unknownSwitchContext(gaps []string) bool {
	for _, gap := range gaps {
		switch gap {
		case "effective tagged VLANs", "SSIDs":
			continue
		default:
			return true
		}
	}
	return false
}
