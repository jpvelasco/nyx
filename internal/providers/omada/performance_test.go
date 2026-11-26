package omadaprovider

import (
	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/topology"
	"net/http"
	"strings"
	"testing"
)

func TestOmadaPerformancePortAndChannel(t *testing.T) {
	duplicate := false
	const mac = "02:aa:bb:cc:dd:02"
	ts := omadaServer(t, func(w http.ResponseWriter, r *http.Request) {
		var rows string
		switch path := strings.TrimPrefix(r.URL.Path, "/openapi/v1/abc123/sites/s1/"); path {
		case "/openapi/authorize/token":
			rows = `{"accessToken":"token"}`
		case "/openapi/v1/abc123/sites":
			rows = `[{"id":"s1"}]`
		case "switches/ports/counters":
			row := `{"port":8,"switchMac":"` + mac + `","linkSpeed":0,"rxErrors":1,"portStatus":{"linkStatus":1,"linkSpeed":3,"rxRate":500}}`
			rows = `[` + row + `]`
			if duplicate {
				rows = `[` + row + `,` + row + `]`
			}
		case "dashboard/channels":
			rows = `{"5g channel stat":[{"channel":36,"channelUtilization":87}]}`
		case "aps/02-aa-bb-cc-dd-03/radios":
			rows = `{"wp5g":{"actualChannel":"36","interUtil":43}}`
		default:
			t.Error("unexpected path")
		}
		writeEnvelope(w, 0, "", rows)
	})
	p := &OmadaProvider{}
	opts := providers.ImportOptions{Host: ts.URL, ClientID: "client", ClientSecret: "secret", SkipTLSVerify: true}
	read := func(target topology.PerformanceTarget) topology.PassiveSample {
		t.Helper()
		s, err := p.ObservePerformance(t.Context(), opts, target)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	port := topology.PerformanceTarget{Kind: "switch_port", Port: 8, SwitchMAC: mac}
	if s := read(port); s.ConfiguredSpeed == nil || *s.ConfiguredSpeed != 0 || s.ObservedMbps == nil || *s.ObservedMbps != 1000 || s.RxRate == nil || s.LinkUp == nil || !*s.LinkUp {
		t.Fatal(s)
	}
	duplicate = true
	if s := read(port); s.Status != "ambiguous" {
		t.Fatal(s)
	}
	if s := read(topology.PerformanceTarget{Kind: "channel", Band: "5g", Channel: 36, APMAC: "02:aa:bb:cc:dd:03"}); s.Interference == nil || *s.Interference != 43 || s.Utilization == nil || *s.Utilization != 87 {
		t.Fatal(s)
	}
}
