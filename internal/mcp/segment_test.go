package mcp

import (
	"context"
	"github.com/jpvelasco/nyx/internal/service"
	"net/netip"
	"testing"
)

type segmentTopology struct{}

func (segmentTopology) Report(context.Context, service.TopologyOptions) (*service.TopologyReport, error) {
	return &service.TopologyReport{}, nil
}
func TestSegmentMCPBoundaries(t *testing.T) {
	hermeticCreds(t)
	s := newTestServer()
	s.segmentSvc = service.SegmentService{Topology: segmentTopology{}}
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
}
