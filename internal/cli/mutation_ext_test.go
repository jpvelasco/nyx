package cli

import (
	"strings"
	"testing"

	omadaprov "github.com/jpvelasco/nyx/internal/providers/omada"
	opnsenseprov "github.com/jpvelasco/nyx/internal/providers/opnsense"
	"github.com/spf13/cobra"
)

func TestMutationExtrasRegistered(t *testing.T) {
	ensureProviderRegistered(t, "omada", &omadaprov.OmadaProvider{})
	ensureProviderRegistered(t, "opnsense", &opnsenseprov.Provider{})
	fresh := &cobra.Command{Use: "nyx"}
	BuildProviderSubcommands(fresh)
	want := map[string][]string{
		"omada":    {"plan", "apply-acl", "plan-port", "apply-port-profile", "plan-lan", "apply-lan", "plan-ssid", "apply-ssid", "ssids"},
		"opnsense": {"plan-nat", "apply-nat", "plan-vlan", "apply-vlan", "plan-filter", "apply-filter", "plan-unbound-override", "apply-unbound-override", "list-vlans"},
	}
	for vendor, cmds := range want {
		var v *cobra.Command
		for _, c := range fresh.Commands() {
			if c.Name() == vendor || c.Use == vendor {
				v = c
			}
		}
		if v == nil {
			t.Fatalf("missing vendor %s", vendor)
		}
		have := map[string]bool{}
		for _, c := range v.Commands() {
			have[c.Name()] = true
		}
		for _, name := range cmds {
			if !have[name] {
				t.Errorf("%s missing extra %s", vendor, name)
			}
		}
	}
}

func TestOmadaApplyACLFlagsRequired(t *testing.T) {
	cmd := buildOmadaApplyACLCmd()
	if err := cmd.RunE(cmd, nil); err == nil || !strings.Contains(err.Error(), "--from is required") {
		t.Fatalf("err = %v", err)
	}
	cmd = buildOmadaApplyACLCmd()
	_ = cmd.Flags().Set("from", "trusted")
	if err := cmd.RunE(cmd, nil); err == nil || !strings.Contains(err.Error(), "--to is required") {
		t.Fatalf("err = %v", err)
	}
	cmd = buildOmadaApplyACLCmd()
	_ = cmd.Flags().Set("from", "trusted")
	_ = cmd.Flags().Set("to", "iot")
	if err := cmd.RunE(cmd, nil); err == nil || !strings.Contains(err.Error(), "--action is required") {
		t.Fatalf("err = %v", err)
	}
	cmd = buildOmadaApplyACLCmd()
	_ = cmd.Flags().Set("from", "trusted")
	_ = cmd.Flags().Set("to", "iot")
	_ = cmd.Flags().Set("action", "deny")
	_ = cmd.Flags().Set("protocols", "tcp")
	if err := cmd.RunE(cmd, nil); err == nil || !strings.Contains(err.Error(), "protocol numbers") {
		t.Fatalf("err = %v", err)
	}
}

func TestOmadaPortAndLANFlagValidation(t *testing.T) {
	if _, err := (omadaPortFlags{}).request(); err == nil || !strings.Contains(err.Error(), "--switch-mac") {
		t.Fatalf("port empty = %v", err)
	}
	if _, err := (omadaPortFlags{switchMAC: "aa:bb"}).request(); err == nil || !strings.Contains(err.Error(), "--port") {
		t.Fatalf("port missing = %v", err)
	}
	if _, err := (omadaPortFlags{switchMAC: "aa:bb", port: 1}).request(); err == nil || !strings.Contains(err.Error(), "--native") {
		t.Fatalf("native missing = %v", err)
	}
	req, err := (omadaPortFlags{switchMAC: "aa:bb", port: 2, native: "trusted", tagged: "iot,guest"}).request()
	if err != nil || req.Port != 2 || len(req.Tagged) != 2 {
		t.Fatalf("port req = %+v %v", req, err)
	}
	if _, err := (omadaLANFlags{}).request(); err == nil || !strings.Contains(err.Error(), "--name") {
		t.Fatalf("lan empty = %v", err)
	}
	lan, err := (omadaLANFlags{name: "iot", vlan: 60}).request()
	if err != nil || lan.Name != "iot" || lan.VLAN != 60 {
		t.Fatalf("lan = %+v %v", lan, err)
	}
}

func TestOmadaPlanRequiresSpec(t *testing.T) {
	saveRestoreGlobals(t)
	specFile = ""
	cmd := buildOmadaPlanCmd()
	if err := cmd.RunE(cmd, nil); err == nil || !strings.Contains(err.Error(), "--spec is required") {
		t.Fatalf("plan = %v", err)
	}
}

func TestOpnsenseNatFlagValidation(t *testing.T) {
	if _, err := (opnsenseNatFlags{}).request(); err == nil || !strings.Contains(err.Error(), "--operation") {
		t.Fatalf("nat empty = %v", err)
	}
	if _, err := (opnsenseNatFlags{operation: "port_forward", action: "delete"}).request(); err == nil || !strings.Contains(err.Error(), "--rule-uuid") {
		t.Fatalf("nat delete = %v", err)
	}
	req, err := (opnsenseNatFlags{operation: "port_forward", interfaces: "wan", source: "any", destination: "10.0.10.20"}).request()
	if err != nil || req.Operation != "port_forward" {
		t.Fatalf("nat req = %+v %v", req, err)
	}
}

func TestOpnsenseVLANFilterUnboundRequests(t *testing.T) {
	v := (opnsenseVLANFlags{parent: "igb0", tag: 60, members: "igb0,igb1"}).request()
	if v.Parent != "igb0" || v.Tag != 60 || len(v.Members) != 2 {
		t.Fatalf("vlan = %+v", v)
	}
	f := (opnsenseFilterFlags{source: "lan", destination: "iot", action: "block"}).request()
	if f.Source != "lan" || f.Action != "block" {
		t.Fatalf("filter = %+v", f)
	}
	u := (opnsenseUnboundFlags{hostname: "nas", domain: "home.example", ip: "10.0.40.10"}).request()
	if u.Hostname != "nas" || u.IP != "10.0.40.10" {
		t.Fatalf("unbound = %+v", u)
	}
}

func TestApplyCommandsDefaultDryRun(t *testing.T) {
	for _, cmd := range []*cobra.Command{
		buildOmadaApplyACLCmd(),
		buildOmadaApplyPortProfileCmd(),
		buildOmadaApplyLANCmd(),
		buildOmadaApplySSIDCmd(),
		buildOpnsenseApplyNatCmd(),
		buildOpnsenseApplyVLANCmd(),
		buildOpnsenseApplyFilterCmd(),
		buildOpnsenseApplyUnboundCmd(),
	} {
		f := cmd.Flags().Lookup("dry-run")
		if f == nil {
			t.Errorf("%s missing --dry-run", cmd.Name())
			continue
		}
		if f.DefValue != "true" {
			t.Errorf("%s dry-run default = %q, want true", cmd.Name(), f.DefValue)
		}
	}
}

func TestMutationCommandBuildersHaveRunE(t *testing.T) {
	for _, cmd := range []*cobra.Command{
		buildOpnsensePlanNatCmd(),
		buildOpnsensePlanVLANCmd(),
		buildOpnsensePlanFilterCmd(),
		buildOpnsensePlanUnboundCmd(),
		buildOmadaPlanPortCmd(),
		buildOmadaPlanLANCmd(),
		buildOmadaPlanSSIDCmd(),
		buildOmadaListSSIDsCmd(),
		buildOmadaApplyACLCmd(),
		buildOpnsenseApplyNatCmd(),
	} {
		if cmd.RunE == nil {
			t.Errorf("%s has no RunE", cmd.Use)
		}
	}
}
