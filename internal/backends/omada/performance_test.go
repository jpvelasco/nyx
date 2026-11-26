package omada

import (
	"net/http"
	"strings"
	"testing"
)

func TestPassivePortAndRadioMetrics(t *testing.T) {
	ambiguous := false
	missing := false
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Error("non-read performance request")
		}
		rows := ""
		switch {
		case strings.HasSuffix(r.URL.Path, "/ports/counters"):
			rows = `[{"port":8,"txBytes":0,"rxErrors":3,"portStatus":{"linkStatus":1,"linkSpeed":2}}]`
		case strings.HasSuffix(r.URL.Path, "/dashboard/channels"):
			rows = `{"5g channel stat":[{"channel":36,"channelUtilization":null}]}`
		case strings.HasSuffix(r.URL.Path, "/radios"):
			rows = `{"wp5g":{"actualChannel":"36 / 5180MHz","interUtil":45},"wp2g":{"actualChannel":"6","interUtil":10}}`
			if ambiguous {
				rows = `{"wp5g":{"actualChannel":"36","interUtil":45},"wp5g2":{"actualChannel":"36","interUtil":50}}`
			}
			if missing {
				rows = `{"wp5g":{"actualChannel":"36","interUtil":101}}`
			}
		default:
			t.Error("unexpected path")
		}
		writeEnvelope(w, 0, "", rows)
	}))
	rows, err := c.PortCounters(t.Context(), "s1")
	if err != nil || len(rows) != 1 || rows[0].TxBytes == nil || *rows[0].TxBytes != 0 || rows[0].RxBytes != nil {
		t.Fatal(rows, err)
	}
	ch, err := c.ChannelUsage(t.Context(), "s1")
	if err != nil || ch["5g channel stat"][0].Utilization != nil {
		t.Fatal(ch, err)
	}
	ap := "02:aa:bb:cc:dd:03"
	read := func() *float64 {
		t.Helper()
		pct, err := c.RadioInterference(t.Context(), "s1", ap, "5g", 36)
		if err != nil {
			t.Fatal(err)
		}
		return pct
	}
	if p := read(); p == nil || *p != 45 {
		t.Fatal(p)
	}
	ambiguous = true
	if p := read(); p != nil {
		t.Fatal("ambiguous dual radio reading")
	}
	missing = true
	if p := read(); p != nil {
		t.Fatal("out of bounds percentage")
	}
}
