package service

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/topology"
)

// stubTopoForPlaybook serves canned topology reports to the playbook
// tests — generic role names only, no site-specific identifiers (#140).
type stubTopoForPlaybook struct {
	rep *TopologyReport
	err error
}

func (s *stubTopoForPlaybook) Report(_ context.Context, _ TopologyOptions) (*TopologyReport, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.rep, nil
}

// stubOpnsenseNat pins the OPNsense service's plan/apply behavior.
type stubOpnsenseNat struct {
	plan        *providers.NatPlan
	apply       *providers.NatApplyResult
	err         error
	applyCalled bool
	applyDryRun bool
}

func (s *stubOpnsenseNat) PlanNat(_ context.Context, _ OpnsenseOptions, _ OpnsenseNatApplyRequest) (*providers.NatPlan, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.plan, nil
}

func (s *stubOpnsenseNat) ApplyNat(_ context.Context, _ OpnsenseOptions, req OpnsenseNatApplyRequest) (*providers.NatApplyResult, error) {
	s.applyCalled = true
	s.applyDryRun = req.DryRun
	if s.err != nil {
		return nil, s.err
	}
	return s.apply, nil
}

// stubOmadaNat pins the Omada service's plan/apply behavior (the #139
// HOLD).
type stubOmadaNat struct {
	plan  *providers.NatPlan
	apply *providers.NatApplyResult
	err   error
}

func (s *stubOmadaNat) PlanNat(_ context.Context, _ OmadaOptions, _ OmadaNatApplyRequest) (*providers.NatPlan, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.plan, nil
}

func (s *stubOmadaNat) ApplyNat(_ context.Context, _ OmadaOptions, _ OmadaNatApplyRequest) (*providers.NatApplyResult, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.apply, nil
}

func playbookService(topo *stubTopoForPlaybook, opnsense *stubOpnsenseNat, omada *stubOmadaNat) *PlaybookService {
	svc := &PlaybookService{
		Topology: topo,
	}
	if opnsense != nil {
		svc.Opnsense = opnsense
	}
	if omada != nil {
		svc.Omada = omada
	}
	return svc
}

func testPlaybookOptions(provider string) PlaybookOptions {
	switch provider {
	case "opnsense":
		return PlaybookOptions{Opnsense: &OpnsenseOptions{Host: "opnsense.example"}}
	default:
		return PlaybookOptions{Omada: &OmadaOptions{Host: "omada.example", ClientID: "cid", ClientSecret: "pw"}}
	}
}

func onPathNatRouter(provider string) *TopologyReport {
	return &TopologyReport{
		Devices: []topology.DeviceReport{
			{Provider: provider, Role: topology.RoleNatRouter, OnPath: true},
		},
		Risk: string(topology.RiskNone),
	}
}

// TestPlanPortForwardRoutesToOpnsense pins the composed routing (#140):
// when the topology reports OPNsense as the on-path NAT router, the
// playbook delegates the plan to the OPNsense NAT surface and carries
// the decision trail.
func TestPlanPortForwardRoutesToOpnsense(t *testing.T) {
	opnsense := &stubOpnsenseNat{plan: &providers.NatPlan{Provider: "opnsense", Outcome: "would_create"}}
	svc := playbookService(&stubTopoForPlaybook{rep: onPathNatRouter("opnsense")}, opnsense, nil)

	plan, err := svc.PlanPortForward(context.Background(), testPlaybookOptions("opnsense"), PortForwardRequest{
		ExternalPort: "443",
		Target:       "10.0.40.10",
		LocalPort:    "443",
		Protocol:     "tcp",
	})
	if err != nil {
		t.Fatalf("PlanPortForward: %v", err)
	}
	if plan.Provider != "opnsense" || plan.Decision != PlaybookDecisionNatOwner {
		t.Errorf("plan = %+v, want the opnsense NAT owner routing", plan)
	}
	if plan.Outcome != "would_create" {
		t.Errorf("outcome = %q, want the delegated plan outcome", plan.Outcome)
	}
	if !strings.Contains(plan.Playbook, "nat_router") || !strings.Contains(plan.Playbook, "none") {
		t.Errorf("the playbook trail should record the topology signal and risk: %q", plan.Playbook)
	}
}

// TestPlanPortForwardOmadaOwnerHolds pins the other routing (#139+#140):
// when the managed Omada gateway owns the egress NAT, the playbook routes
// to the Omada surface — which refuses with the write-surface
// explanation — and the playbook reports the hold honestly.
func TestPlanPortForwardOmadaOwnerHolds(t *testing.T) {
	omada := &stubOmadaNat{plan: &providers.NatPlan{Provider: "omada", Outcome: "refused",
		Warnings: []string{"the Omada Open API exposes NAT reads but no live-site NAT write path"}}}
	svc := playbookService(&stubTopoForPlaybook{rep: onPathNatRouter("omada")}, nil, omada)

	plan, err := svc.PlanPortForward(context.Background(), testPlaybookOptions("omada"), PortForwardRequest{
		ExternalPort: "443", Target: "10.0.40.10", Protocol: "tcp",
	})
	if err != nil {
		t.Fatalf("PlanPortForward: %v", err)
	}
	if plan.Provider != "omada" || plan.Decision != PlaybookDecisionNatOwner {
		t.Errorf("plan = %+v, want the omada NAT owner routing", plan)
	}
	if plan.Outcome != "refused" {
		t.Errorf("outcome = %q, want the omada hold", plan.Outcome)
	}
	if len(plan.Warnings) == 0 {
		t.Error("the hold explanation must reach the playbook output")
	}
}

// TestPlanPortForwardRefusesDoubleNat pins the safety gate: a
// double-NAT topology is never routed to a mutation surface from the
// composed playbook — resolve the topology first.
func TestPlanPortForwardRefusesDoubleNat(t *testing.T) {
	opnsense := &stubOpnsenseNat{plan: &providers.NatPlan{Outcome: "would_create"}}
	svc := playbookService(&stubTopoForPlaybook{rep: &TopologyReport{
		Devices: []topology.DeviceReport{
			{Provider: "omada", Role: topology.RoleNatRouter, OnPath: true},
			{Provider: "opnsense", Role: topology.RoleNatRouter, OnPath: true},
		},
		Risk: string(topology.RiskDouble),
	}}, opnsense, nil)

	plan, err := svc.PlanPortForward(context.Background(), testPlaybookOptions("opnsense"), PortForwardRequest{ExternalPort: "443", Target: "10.0.40.10"})
	if err != nil {
		t.Fatalf("PlanPortForward: %v", err)
	}
	if plan.Outcome != PlaybookOutcomeRefused {
		t.Errorf("outcome = %q, want refused under double NAT", plan.Outcome)
	}
	if plan.Decision != PlaybookDecisionUnsafe {
		t.Errorf("decision = %q, want the unsafe-topology decision", plan.Decision)
	}
}

// TestPlanPortForwardRefusesIndeterminate pins the unknown-topology
// routing: with no on-path NAT router and indeterminate facts, the
// playbook refuses without dispatching to any provider.
func TestPlanPortForwardRefusesIndeterminate(t *testing.T) {
	opnsense := &stubOpnsenseNat{plan: &providers.NatPlan{Outcome: "would_create"}}
	svc := playbookService(&stubTopoForPlaybook{rep: &TopologyReport{
		Devices: []topology.DeviceReport{
			{Provider: "opnsense", Role: topology.RoleIndeterminate, OnPath: true},
		},
		Risk: string(topology.RiskIndeterminate),
	}}, opnsense, nil)

	plan, err := svc.PlanPortForward(context.Background(), testPlaybookOptions("opnsense"), PortForwardRequest{ExternalPort: "443", Target: "10.0.40.10"})
	if err != nil {
		t.Fatalf("PlanPortForward: %v", err)
	}
	if plan.Outcome != PlaybookOutcomeRefused || plan.Decision != PlaybookDecisionIndeterminate {
		t.Errorf("plan = %+v, want an indeterminate refusal", plan)
	}
}

// TestPlanPortForwardNoProviders is the actionable error: with nothing
// configured there is no topology to compose from.
func TestPlanPortForwardNoProviders(t *testing.T) {
	svc := playbookService(&stubTopoForPlaybook{}, nil, nil)
	if _, err := svc.PlanPortForward(context.Background(), PlaybookOptions{}, PortForwardRequest{ExternalPort: "443", Target: "10.0.40.10"}); err == nil {
		t.Fatal("expected an error when no providers are configured")
	}
}

// TestPlanPortForwardTopologyError propagates a broken observation with
// context.
func TestPlanPortForwardTopologyError(t *testing.T) {
	svc := playbookService(&stubTopoForPlaybook{err: errors.New("controller down")}, nil, nil)
	if _, err := svc.PlanPortForward(context.Background(), testPlaybookOptions("opnsense"), PortForwardRequest{ExternalPort: "443", Target: "10.0.40.10"}); err == nil ||
		!strings.Contains(err.Error(), "controller down") {
		t.Fatalf("expected the topology error to propagate, got %v", err)
	}
}

// TestApplyPortForwardDelegatesWithDryRun pins the apply routing and
// the dry-run default posture: the selected provider's apply receives
// the dry-run flag unchanged (the repository's mutation posture).
func TestApplyPortForwardDelegatesWithDryRun(t *testing.T) {
	opnsense := &stubOpnsenseNat{apply: &providers.NatApplyResult{Provider: "opnsense", Outcome: "created"}}
	svc := playbookService(&stubTopoForPlaybook{rep: onPathNatRouter("opnsense")}, opnsense, nil)
	pbOpts := testPlaybookOptions("opnsense")

	// Dry-run (the default) reaches the provider with DryRun set.
	res, err := svc.ApplyPortForward(context.Background(), pbOpts, PortForwardRequest{ExternalPort: "443", Target: "10.0.40.10"}, true)
	if err != nil {
		t.Fatalf("ApplyPortForward: %v", err)
	}
	if res.Outcome != "created" || !opnsense.applyDryRun {
		t.Errorf("res = %+v applyDryRun = %v, want the delegated dry-run apply", res, opnsense.applyDryRun)
	}

	// A real apply passes DryRun=false through.
	opnsense.applyDryRun = true
	if _, err := svc.ApplyPortForward(context.Background(), pbOpts, PortForwardRequest{ExternalPort: "443", Target: "10.0.40.10"}, false); err != nil {
		t.Fatalf("ApplyPortForward real: %v", err)
	}
	if opnsense.applyDryRun {
		t.Error("the real apply must reach the provider with dry-run cleared")
	}
}

// TestApplyPortForwardRefusesDoubleNat: the safety gate holds on apply
// too — nothing is dispatched under double NAT.
func TestApplyPortForwardRefusesDoubleNat(t *testing.T) {
	opnsense := &stubOpnsenseNat{apply: &providers.NatApplyResult{Outcome: "created"}}
	svc := playbookService(&stubTopoForPlaybook{rep: &TopologyReport{
		Devices: []topology.DeviceReport{
			{Provider: "omada", Role: topology.RoleNatRouter, OnPath: true},
			{Provider: "opnsense", Role: topology.RoleNatRouter, OnPath: true},
		},
		Risk: string(topology.RiskDouble),
	}}, opnsense, nil)

	res, err := svc.ApplyPortForward(context.Background(), testPlaybookOptions("opnsense"), PortForwardRequest{ExternalPort: "443", Target: "10.0.40.10"}, false)
	if err != nil {
		t.Fatalf("ApplyPortForward: %v", err)
	}
	if res.Outcome != PlaybookOutcomeRefused || opnsense.applyCalled {
		t.Errorf("res = %+v, provider dispatched = %v — double NAT must refuse without dispatch", res, opnsense.applyCalled)
	}
}

// TestPortForwardRequestValidation pins the playbook's request shape.
func TestPortForwardRequestValidation(t *testing.T) {
	cases := []struct {
		req  PortForwardRequest
		want string
	}{
		{PortForwardRequest{}, "external_port"},
		{PortForwardRequest{ExternalPort: "443"}, "target"},
	}
	for _, tc := range cases {
		if err := tc.req.Validate(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Validate() = %v, want an error naming %q", err, tc.want)
		}
	}
	if err := (PortForwardRequest{ExternalPort: "443", Target: "10.0.40.10"}).Validate(); err != nil {
		t.Errorf("external port + target is a valid minimal request: %v", err)
	}
}
