package service

import (
	"context"
	"fmt"

	topology "github.com/jpvelasco/nyx/internal/topology"
)

// TopologyOptions selects which providers to observe. Both can be set
// (the common case: Omada gateway upstream of an in-line OPNsense box) or
// either one alone. The credentials come from the per-provider options —
// this struct only says what to ask each one for.
type TopologyOptions struct {
	Omada    *OmadaOptions    // nil = do not observe Omada
	Opnsense *OpnsenseOptions // nil = do not observe OPNsense
}

// TopologyReport is the agent-facing topology assessment: per-provider NAT
// posture plus the combined double-NAT risk. The NAT summaries are the
// evidence; the risk verdict is derived from them.
type TopologyReport struct {
	Omada    *OmadaNatFacts          `json:"omada,omitempty"`
	Opnsense *OpnsenseNatSummary     `json:"opnsense,omitempty"`
	Devices  []topology.DeviceReport `json:"devices"`
	Risk     string                  `json:"risk"`
	Reason   string                  `json:"reason"`
}

// TopologyService composes the Omada and OPNsense observation surfaces into
// a topology assessment. It is read-only: it issues only GETs.
type TopologyService struct {
	Omada    *OmadaService
	Opnsense *OpnsenseService
}

// NewTopologyService creates a TopologyService over the real observation
// services.
func NewTopologyService() *TopologyService {
	return &TopologyService{
		Omada:    NewOmadaService(),
		Opnsense: NewOpnsenseService(),
	}
}

// Report gathers the NAT posture from each configured provider and derives
// the double-NAT risk. At least one provider must be configured; a fetch
// failure from either is a hard error — a partial picture would produce a
// confidently wrong verdict.
func (s *TopologyService) Report(ctx context.Context, opts TopologyOptions) (*TopologyReport, error) {
	if opts.Omada == nil && opts.Opnsense == nil {
		return nil, fmt.Errorf("topology report needs at least one provider configured (omada and/or opnsense)")
	}

	rep := &TopologyReport{Devices: []topology.DeviceReport{}}
	var facts []topology.DeviceFacts

	if opts.Omada != nil {
		omadaFacts, err := s.Omada.NatFacts(ctx, *opts.Omada)
		if err != nil {
			return nil, fmt.Errorf("observing omada: %w", err)
		}
		rep.Omada = omadaFacts
		facts = append(facts, topology.DeviceFacts{
			Provider:          topology.ProviderOmada,
			HasManagedGateway: omadaFacts.HasManagedGateway,
			PortForwardRules:  omadaFacts.PortForwardRules,
			OneToOneRules:     omadaFacts.OneToOneRules,
		})
	}

	if opts.Opnsense != nil {
		nat, err := s.Opnsense.GetNAT(ctx, *opts.Opnsense)
		if err != nil {
			return nil, fmt.Errorf("observing opnsense: %w", err)
		}
		rep.Opnsense = nat
		facts = append(facts, topology.DeviceFacts{
			Provider:         topology.ProviderOpnsense,
			OutboundNatMode:  nat.OutboundNatMode,
			SourceNatRules:   len(nat.SourceNatRules),
			PortForwardRules: len(nat.PortForwardRules),
			OneToOneRules:    len(nat.OneToOneRules),
		})
	}

	classified := topology.BuildReport(facts)
	rep.Devices = classified.Devices
	rep.Risk = string(classified.Risk)
	rep.Reason = classified.Reason
	return rep, nil
}
