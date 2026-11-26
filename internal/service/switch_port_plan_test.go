package service

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/credentials"
	"github.com/jpvelasco/nyx/internal/providers"
	omadaprovider "github.com/jpvelasco/nyx/internal/providers/omada"
	"github.com/jpvelasco/nyx/internal/testutil/providerfixture"
	"github.com/jpvelasco/nyx/internal/topology"
)

func TestSwitchPortPlanUncertainAttachments(t *testing.T) {
	providerfixture.IsolateProviders(t)
	if err := providers.Register(&omadaprovider.OmadaProvider{}); err != nil {
		t.Fatal(err)
	}
	const sw = "aa:bb:cc:dd:ee:01"
	const mac = "02:aa:bb:cc:dd:04"
	clientRows := `[{"mac":"` + mac + `"}]`
	failLLDP := false
	st := omadaPortStateFresh()
	base := omadaPortBaseHandler(t, st)
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasSuffix(path, "/networks/client"):
			writeOmadaEnvelope(w, 0, clientRows)
		case strings.HasSuffix(path, "/client-link-topology"):
			m := mac
			if strings.Contains(path, "dd-05/") {
				m = "02:aa:bb:cc:dd:05"
			}
			writeOmadaEnvelope(w, 0, `[{"nodeType":"clientNode","clientNode":{"mac":"`+m+`","upOswInfo":{"mac":"`+sw+`","port":"1"}}}]`)
		case strings.HasSuffix(path, "/networks/devices"):
			writeOmadaEnvelope(w, 0, `[{"type":"switch","mac":"`+sw+`"}]`)
		case strings.HasSuffix(path, "/lldp-neighbors"):
			if failLLDP {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			writeOmadaEnvelope(w, 0, "[]")
		case strings.HasSuffix(path, "/ssids"):
			writeOmadaEnvelope(w, 0, "[]")
		default:
			base(w, r)
		}
	})
	path := filepath.Join(t.TempDir(), "credentials.json")
	t.Setenv("NYX_CREDENTIALS_FILE", path)
	store, err := credentials.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Set("omada", "home", credentials.Entry{"host": ts.URL, "client_id": "key", "client_secret": "secret"}); err != nil {
		t.Fatal(err)
	}
	policy, err := DecodeSwitchPortPolicy(`{"management_vlan":11,"ports":[{"port":1,"role":"access","native":"gaming","client_mac":"` + mac + `"},{"port":20,"role":"access","native":"gaming"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	s := NewTopologyService()
	ctx := t.Context()
	opts := NetworkMapOptions{SkipTLSVerify: true}
	read := func() SwitchPortPlan {
		t.Helper()
		r, err := s.PlanSwitchPorts(ctx, opts, "omada/home", sw, policy)
		if err != nil || len(r.Ports) != 2 {
			t.Fatalf("plan=%+v error=%v", r, err)
		}
		return r
	}
	r := read()
	if !r.Ports[0].Eligible || r.Ports[0].Revision == "" || r.Ports[1].Eligible || r.Sources[0].Profile != "" {
		t.Fatalf("wrong preview: %+v", r)
	}
	clientRows = `[{"mac":"` + mac + `"},{"mac":"02:aa:bb:cc:dd:05"}]`
	r = read()
	if r.Ports[0].Eligible || r.Ports[0].Role != "ambiguous" {
		t.Fatal("shared wired port received a proposal")
	}
	failLLDP = true
	r = read()
	if r.Ports[0].Desired != nil {
		t.Fatal("LLDP outage received a proposal")
	}
	for _, tc := range []struct {
		sel, mac string
		o        NetworkMapOptions
	}{{"opnsense/home", sw, opts}, {"omada/home", "bad", opts}, {"omada/home", sw, NetworkMapOptions{Connections: []string{"omada/other"}}}, {"omada/missing", sw, opts}} {
		if _, err := s.PlanSwitchPorts(ctx, tc.o, tc.sel, tc.mac, policy); err == nil {
			t.Fatal("unresolved switch accepted")
		}
	}
	for _, text := range []string{"bad", "{} {}", `{"management_vlan":11,"unknown":1}`, `{"management_vlan":0}`, `{"management_vlan":11,"ports":[]}`} {
		if _, err := DecodeSwitchPortPolicy(text); err == nil {
			t.Fatal("accepted invalid role policy")
		}
	}
	if _, err := s.PlanSwitchPorts(ctx, opts, "omada/home", sw, topology.SwitchPortPolicy{}); err == nil {
		t.Fatal("empty policy accepted")
	}
}
