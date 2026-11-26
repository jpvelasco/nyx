package opnsense

import (
	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/testutil"
	"github.com/jpvelasco/nyx/internal/topology"
	"net/http"
	"slices"
	"testing"
)

func TestObserveNetworkConflictedInterfaces(t *testing.T) {
	if facts, err := (&Provider{}).ObserveNetwork(t.Context(), providers.ImportOptions{}); err == nil || len(facts.Resources) > 0 {
		t.Fatal("unauthenticated observation accepted")
	}
	failVLAN, failIface := false, false
	_, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/interfaces/vlan_settings/search_item":
			if failVLAN {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			testutil.WriteBody(w, `{"total":2,"rows":[{"uuid":"one","vlanif":"vlan30","tag":"30"},{"uuid":"other","vlanif":"vlan30","tag":"11"}]}`)
		case "/api/interfaces/overview/interfaces_info":
			if failIface {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			testutil.WriteBody(w, `{"rows":[{"identifier":"lan","device":"igb0","link_type":"ether","macaddr":"02:aa:bb:cc:dd:01","enabled":true},{"identifier":"opt1","device":"vlan30","enabled":true,"addr4":"10.0.30.1/24"}]}`)
		default:
			t.Error("unexpected fixture route")
			w.WriteHeader(http.StatusNotFound)
		}
	})
	p := &Provider{}
	opts := providers.ImportOptions{Host: ts.URL, ClientID: "key", ClientSecret: "secret", SkipTLSVerify: true}
	for _, state := range [][2]bool{{false, false}, {false, true}, {true, false}, {true, true}} {
		failVLAN, failIface = state[0], state[1]
		facts, err := p.ObserveNetwork(t.Context(), opts)
		if failVLAN && failIface {
			if err == nil {
				t.Fatal("both collectors unavailable")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if !failVLAN && !slices.Contains(facts.Gaps, "VLAN device identity") {
			t.Fatal("conflicting VLAN device tags accepted")
		}
		if !failIface && len(facts.Resources) < 3 {
			t.Fatal("lost interface inventory")
		}
		if !failVLAN && !failIface {
			m := topology.BuildNetworkMap([]topology.MapInput{{Provider: "opnsense", Facts: facts}}, true)
			for _, l := range m.Links {
				if l.Relation == "gateway" && l.State != "missing" {
					t.Fatal("claimed conflicted interface as serving gateway")
				}
			}
		}
	}
}
