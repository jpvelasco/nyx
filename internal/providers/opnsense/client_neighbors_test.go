package opnsense

import (
	"net/http"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
)

func TestNeighborTables(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Error("neighbor diagnostics must use GET")
		}
		switch r.URL.Path {
		case "/api/diagnostics/interface/get_arp":
			testutil.WriteBody(w, `[{"mac":"02:aa:bb:cc:dd:01","ip":"192.0.2.1","intf":"vlan30","expired":true}]`)
		case "/api/diagnostics/interface/get_ndp":
			testutil.WriteBody(w, `[{"mac":"02:aa:bb:cc:dd:01","ip":"2001:db8::1","intf":"vlan30"}]`)
		default:
			http.NotFound(w, r)
		}
	}))
	arp, err := c.GetARPNeighbors(t.Context())
	if err != nil || len(arp) != 1 || !arp[0].Expired || arp[0].Interface != "vlan30" {
		t.Fatalf("arp: %+v %v", arp, err)
	}
	ndp, err := c.GetNDPNeighbors(t.Context())
	if err != nil || len(ndp) != 1 || ndp[0].Expired || ndp[0].IP != "2001:db8::1" {
		t.Fatalf("ndp: %+v %v", ndp, err)
	}
}
