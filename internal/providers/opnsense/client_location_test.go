package opnsense

import (
	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/testutil"
	"net/http"
	"slices"
	"testing"
)

func TestLocateClientLeaseAndExpiredCache(t *testing.T) {
	const mac = "02:aa:bb:cc:dd:04"
	outage := false
	_, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if outage {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var body string
		switch r.URL.Path {
		case "/api/dnsmasq/settings/get":
			body = `{"dnsmasq":{"enable":"1"}}`
		case "/api/dnsmasq/leases/search":
			body = `{"rows":[{"hwaddr":"` + mac + `","address":"192.0.2.2"}]}`
		case "/api/diagnostics/interface/get_arp":
			body = `[{"mac":"` + mac + `","ip":"192.0.2.2","expired":true},{"mac":"02:aa:bb:cc:dd:01"}]`
		case "/api/diagnostics/interface/get_ndp":
			body = `[{"mac":"` + mac + `","ip":"2001:db8::1"}]`
		default:
			t.Error("unexpected fixture route")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		testutil.WriteBody(w, body)
	})
	opts := providers.ImportOptions{Host: ts.URL, ClientID: "key", ClientSecret: "secret", SkipTLSVerify: true}
	p := &Provider{}
	e, gaps, err := p.ObserveClient(t.Context(), opts, mac)
	if err != nil || len(e) != 3 || len(gaps) != 0 || e[0].Kind != "DHCP lease" || e[1].Status != "expired" || e[2].Kind != "NDP" {
		t.Fatal(e, gaps, err)
	}
	outage = true
	e, gaps, err = p.ObserveClient(t.Context(), opts, mac)
	if err != nil || len(e) != 0 || !slices.Contains(gaps, "ARP table") || !slices.Contains(gaps, "DHCP lease inventory") || !slices.Contains(gaps, "NDP table") {
		t.Fatal(e, gaps, err)
	}
	if _, _, err := p.ObserveClient(t.Context(), opts, "bad"); err == nil {
		t.Fatal("invalid client selector")
	}
	if _, _, err := p.ObserveClient(t.Context(), providers.ImportOptions{}, mac); err == nil {
		t.Fatal("missing credentials")
	}
}
