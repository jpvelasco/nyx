package omadaprovider

import (
	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/topology"
	"net/http"
	"slices"
	"strings"
	"testing"
)

func TestClientObservationSources(t *testing.T) {
	mode := "wired"
	const wanted = "02:aa:bb:cc:dd:04"
	ts := omadaServer(t, func(w http.ResponseWriter, r *http.Request) {
		var rows string
		switch path := strings.TrimPrefix(r.URL.Path, "/openapi/v1/abc123/sites/s1/"); path {
		case "/openapi/authorize/token":
			rows = `{"accessToken":"token"}`
		case "/openapi/v1/abc123/sites":
			rows = `[{"id":"s1","name":"fixture"}]`
		case "networks/client":
			rows = `[{"mac":"02:aa:bb:cc:dd:09"},{"mac":"` + wanted + `"}]`
			if mode == "offline" {
				rows = `[]`
			}
		case "clients/02-aa-bb-cc-dd-04/client-link-topology":
			switch mode {
			case "wired":
				rows = `[{"nodeType":"deviceNode"},{"nodeType":"clientNode","clientNode":{"mac":"` + wanted + `","upOswInfo":{"mac":"02:aa:bb:cc:dd:02","port":"8"}}}]`
			case "wireless":
				rows = `[{"nodeType":"clientNode","clientNode":{"mac":"` + wanted + `","upApInfo":{"mac":"02:aa:bb:cc:dd:03"}}}]`
			default:
				w.WriteHeader(http.StatusForbidden)
				return
			}
		case "clients/02-aa-bb-cc-dd-04/client-history":
			rows = `[{"mac":"02:aa:bb:cc:dd:09"},{"mac":"` + wanted + `","ssid":"gaming","lastSeen":10}]`
		default:
			t.Error("unexpected fixture route")
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeEnvelope(w, 0, "", rows)
	})
	p := &OmadaProvider{}
	opts := providers.ImportOptions{Host: ts.URL, ClientID: "client", ClientSecret: "secret", SkipTLSVerify: true}
	for _, kind := range []string{"wired", "wireless", "unknown", "offline"} {
		mode = kind
		e, gaps, err := p.ObserveClient(t.Context(), opts, wanted)
		if err != nil || !slices.ContainsFunc(e, func(r topology.ClientObservation) bool {
			return r.Kind == "history" && r.Status == "historical" && r.LastSeen == 10
		}) {
			t.Fatal(e, err)
		}
		switch kind {
		case "wired":
			if e[0].Attachment.Kind != "port" || e[0].Port != 8 {
				t.Fatal(e)
			}
		case "wireless":
			if e[0].Attachment.Kind != "ap" {
				t.Fatal(e)
			}
		case "unknown":
			if !slices.Contains(gaps, "client uplink inventory") || e[0].Attachment.Key != "" {
				t.Fatal(e, gaps)
			}
		case "offline":
			if len(e) != 1 {
				t.Fatal("historical client became current")
			}
		}
	}
}
