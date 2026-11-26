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
	args["omada_host"] = "omada.example"
	args["omada_client_id"] = "client"
	args["omada_client_secret"] = "fixture"
	args["omada_site"] = "site"
	args["opnsense_host"] = "firewall.example"
	args["opnsense_api_key"] = "key"
	args["opnsense_api_secret"] = "fixture"
	call("apply_segment")
}
