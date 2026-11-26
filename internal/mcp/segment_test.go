package mcp

import (
	"net/netip"
	"testing"

	"github.com/jpvelasco/nyx/internal/service"
)

func TestSegmentMCPBoundaries(t *testing.T) {
	hermeticCreds(t)
	s := newTestServer()
	topology := &stubTopoSvc{report: &service.TopologyReport{}}
	s.segmentSvc = service.SegmentService{Topology: topology}
	first := netip.MustParseAddr("10.0.30.1").Next()
	args := map[string]any{"role": "gaming", "tag": float64(30), "parent": "igb0", "management_prefix": "10.0.11.0/24", "gateway": "10.0.30.1/24", "resolver": "10.0.40.1", "pool_start": first.String(), "pool_end": first.Next().String()}
	call := func(tool string) {
		t.Helper()
		if _, bad := s.DispatchToolForTest(t.Context(), tool, args); !bad {
			t.Fatal("invalid request accepted", tool)
		}
	}
	call("plan_segment")
	args["tag"] = 30.5
	call("apply_segment")
	args["tag"] = 30
	args["role"] = "management"
	call("apply_segment")
	args["role"] = "gaming"
	args["dry_run"] = false
	call("plan_segment")
	for _, key := range []string{"omada_host", "opnsense_host", "omada_client_id", "opnsense_api_secret", "omada_skip_tls_verify", "opnsense_ca_cert_path"} {
		args[key] = "override"
		call("apply_segment")
		delete(args, key)
	}
	for k, v := range map[string]string{"OMADA_HOST": "omada.example", "OMADA_CLIENT_ID": "client", "OMADA_CLIENT_SECRET": "fixture", "OPNSENSE_HOST": "firewall.example", "OPNSENSE_API_KEY": "key", "OPNSENSE_API_SECRET": "fixture"} {
		t.Setenv(k, v)
	}
	args["omada_site"] = "site"
	call("apply_segment")
	delete(args, "dry_run")
	t.Setenv("NYX_OMADA_CA_CERT", "omada.pem")
	t.Setenv("NYX_OPNSENSE_CA_CERT", "firewall.pem")
	for _, explicit := range []bool{false, true, false} {
		if explicit {
			args["skip_tls_verify"] = true
			args["ca_cert_path"] = "both.pem"
		} else {
			delete(args, "skip_tls_verify")
			delete(args, "ca_cert_path")
		}
		before := topology.calls
		call("plan_segment") // The fixture has no routing owner.
		if topology.calls != before+1 {
			t.Fatal("plan did not reach topology observation")
		}
		omada, firewall := topology.opts.Omada, topology.opts.Opnsense
		if omada.SkipTLSVerify != explicit || firewall.SkipTLSVerify != explicit {
			t.Fatal("incorrect certificate verification setting")
		}
		wantOmada, wantFirewall := "omada.pem", "firewall.pem"
		if explicit {
			wantOmada, wantFirewall = "both.pem", "both.pem"
		}
		if omada.CACertPath != wantOmada || firewall.CACertPath != wantFirewall {
			t.Fatal("incorrect provider CA paths")
		}
	}
	for _, provider := range []string{"omada", "opnsense"} {
		key := provider + "_profile"
		args[key] = "missing"
		before := topology.calls
		call("plan_segment")
		if topology.calls != before {
			t.Errorf("used default credentials for missing %s profile", provider)
		}
		delete(args, key)
	}
}
