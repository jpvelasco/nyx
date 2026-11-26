package opnsense

import (
	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/testutil"
	"github.com/jpvelasco/nyx/internal/topology"
	"net/http"
	"testing"
)

func TestFirewallPerformanceEvidence(t *testing.T) {
	invalid := false
	_, ts := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		var body string
		switch r.URL.Path {
		case "/api/trafficshaper/service/statistics":
			body = `{"status":"ok","items":[{"type":"pipe","id":"other"},{"type":"queue","id":"1.1","flows":[{"Source":"192.0.2.1","Destination":"192.0.2.2","Prot":"tcp","drop_pkt":0}]}]}`
			if invalid {
				body = `{"status":"ok","items":[{"type":"queue","id":"1.1","flows":[{}]}]}`
			}
		case "/api/routes/gateway/status":
			body = `{"items":[{"name":"gateway","delay":"4.5 ms","loss":"1%"}]}`
			if invalid {
				body = `{"items":[{"name":"gateway","delay":"NaN","loss":"110%"}]}`
			}
		case "/api/interfaces/overview/interfaces_info":
			body = `{"rows":[{"identifier":"opt1","statistics":{"rx":{"bytes":0}}}]}`
		default:
			t.Error("unknown performance path")
		}
		testutil.WriteBody(w, body)
	})
	opts := providers.ImportOptions{Host: ts.URL, ClientID: "key", ClientSecret: "secret", SkipTLSVerify: true}
	p := &Provider{}
	read := func(kind, name string) topology.PassiveSample {
		t.Helper()
		s, err := p.ObservePerformance(t.Context(), opts, topology.PerformanceTarget{Kind: kind, Name: name})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	if s := read("interface", "opt1"); s.RxBytes == nil || s.TxBytes != nil {
		t.Fatal("missing counter interpreted as zero")
	}
	if s := read("gateway", "gateway"); s.LatencyMS == nil || *s.LatencyMS != 4.5 || s.Loss == nil {
		t.Fatal(s)
	}
	if s := read("shaper_queue", "1.1"); s.Drops == nil || *s.Drops != 0 || s.FlowSet == "" {
		t.Fatal(s)
	}
	invalid = true
	if s := read("gateway", "gateway"); s.LatencyMS != nil || s.Loss != nil {
		t.Fatal("invalid monitoring sample")
	}
	if s := read("shaper_queue", "1.1"); s.Drops != nil {
		t.Fatal("missing flow counter interpreted as zero")
	}
	if _, err := p.ObservePerformance(t.Context(), providers.ImportOptions{}, topology.PerformanceTarget{}); err == nil {
		t.Fatal("missing credentials")
	}
}
