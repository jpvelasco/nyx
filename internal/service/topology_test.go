package service

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
)

// omadaGatewayServer serves a fully-featured Omada controller: one managed
// gateway, one port-forward, one one-to-one rule.
func omadaGatewayServer(t *testing.T) *httptest.Server {
	t.Helper()
	return omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/openapi/v1/abc123/sites/s1/networks/devices":
			writeOmadaEnvelope(w, 0, `[
				{"id":"d1","name":"GW-CORE","model":"GW-CORE","type":"gateway","mac":"aa:bb:cc:dd:ee:00","ip":"10.0.0.254"}]`)
		case "/openapi/v1/abc123/sites/s1/nat/port-forwardings":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[
				{"id":"pf1","name":"web","status":true,"from":0,"externalPort":"443","forwardIp":"10.0.40.10","forwardPort":"443","protocol":1,"dMZ":false}]}`)
		case "/openapi/v1/abc123/sites/s1/nat/one-to-one-nat":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[
				{"id":"o1","name":"nas","status":true,"internalIp":"10.0.40.20","externalIp":"203.0.113.20","dmz":false}]}`)
		case "/openapi/v1/abc123/sites/s1/nat/alg":
			writeOmadaEnvelope(w, 0, `{"ftp":true}`)
		case "/openapi/v1/abc123/sites/s1/firewall":
			writeOmadaEnvelope(w, 0, `{"icmp":30}`)
		default:
			t.Errorf("unexpected omada path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

// opnsenseNatObserver serves the OPNsense NAT + interfaces endpoints the
// topology report reads. wanGateway is the WAN default gateway advertised
// on interfaces_info (empty = public-looking upstream, i.e. on-path).
// dNatNotFound makes the port-forward endpoint 404 to exercise the
// hard-error path.
func opnsenseNatObserver(t *testing.T, snatMode, wanGateway string, dNatNotFound bool) *httptest.Server {
	t.Helper()
	if wanGateway == "" {
		wanGateway = "203.0.113.254"
	}
	return opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if dNatNotFound && r.URL.Path == "/api/firewall/d_nat/search_rule" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch r.URL.Path {
		case "/api/firewall/source_nat/get":
			testutil.WriteBody(w, testutil.SNATModeBody(snatMode))
		case "/api/firewall/d_nat/search_rule",
			"/api/firewall/one_to_one/search_rule",
			"/api/firewall/source_nat/search_rule":
			testutil.WriteBody(w, `{"total":0,"rows":[]}`)
		case "/api/interfaces/overview/interfaces_info":
			testutil.WriteBody(w, fmt.Sprintf(`{"interfaces":{
				"lan":{"description":"LAN","dhcp":false,"ipv4":"10.0.40.1/24","ipv4_gateway":""},
				"wan":{"description":"WAN","dhcp":true,"ipv4":"10.0.0.10/24","ipv4_gateway":%q}
			}}`, wanGateway))
		default:
			t.Errorf("unexpected opnsense path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
}

func opnsenseDownstreamServer(t *testing.T, snatMode, gatewayIP string) *httptest.Server {
	return opnsenseNatObserver(t, snatMode, gatewayIP, false)
}

func opnsenseNatModeServer(t *testing.T, snatMode string, dNatNotFound bool) *httptest.Server {
	return opnsenseNatObserver(t, snatMode, "", dNatNotFound)
}

func TestTopologyServiceReport(t *testing.T) {
	omadaOpts := func(ts *httptest.Server) *OmadaOptions {
		return &OmadaOptions{Host: ts.URL, ClientID: "a", ClientSecret: "b", SkipTLSVerify: true}
	}
	opnsenseOpts := func(ts *httptest.Server) *OpnsenseOptions {
		return &OpnsenseOptions{Host: ts.URL, APIKey: "key1", APISecret: "secret1", SkipTLSVerify: true}
	}

	t.Run("transparent proxy is not double NAT", func(t *testing.T) {
		// The motivating topology: an Omada gateway (NATing) with an
		// in-line OPNsense box whose source NAT is disabled.
		om := omadaGatewayServer(t)
		op := opnsenseNatModeServer(t, "disabled", false)
		rep, err := NewTopologyService().Report(context.Background(), TopologyOptions{
			Omada:    omadaOpts(om),
			Opnsense: opnsenseOpts(op),
		})
		if err != nil {
			t.Fatalf("Report: %v", err)
		}
		if rep.Risk != "none" {
			t.Errorf("risk = %q, want none (transparent proxy); reason: %s", rep.Risk, rep.Reason)
		}
		if len(rep.Devices) != 2 {
			t.Fatalf("devices = %+v, want 2", rep.Devices)
		}
		if rep.Devices[0].Provider != "omada" || rep.Devices[0].Role != "nat_router" {
			t.Errorf("omada device = %+v", rep.Devices[0])
		}
		if rep.Devices[1].Provider != "opnsense" || rep.Devices[1].Role != "bridge" {
			t.Errorf("opnsense device = %+v", rep.Devices[1])
		}
		if rep.Omada == nil || !rep.Omada.HasManagedGateway || rep.Omada.PortForwardRules != 1 {
			t.Errorf("omada facts = %+v", rep.Omada)
		}
		if rep.Opnsense == nil || rep.Opnsense.OutboundNatMode != "disabled" {
			t.Errorf("opnsense facts = %+v", rep.Opnsense)
		}
	})

	t.Run("two routers is double NAT", func(t *testing.T) {
		om := omadaGatewayServer(t)
		op := opnsenseNatModeServer(t, "automatic", false)
		rep, err := NewTopologyService().Report(context.Background(), TopologyOptions{
			Omada:    omadaOpts(om),
			Opnsense: opnsenseOpts(op),
		})
		if err != nil {
			t.Fatalf("Report: %v", err)
		}
		if rep.Risk != "double_nat" {
			t.Errorf("risk = %q, want double_nat; reason: %s", rep.Risk, rep.Reason)
		}
	})

	t.Run("downstream NAT appliance is not double NAT", func(t *testing.T) {
		// Issue #102: a LAN-side appliance whose WAN default gateway is
		// the managed gateway is a client, not an egress hop.
		om := omadaGatewayServer(t)
		// WAN default gateway matches the Omada gateway address from
		// omadaGatewayServer — the box is a LAN client, not an egress hop.
		op := opnsenseDownstreamServer(t, "automatic", "10.0.0.254")
		rep, err := NewTopologyService().Report(context.Background(), TopologyOptions{
			Omada:    omadaOpts(om),
			Opnsense: opnsenseOpts(op),
		})
		if err != nil {
			t.Fatalf("Report: %v", err)
		}
		if rep.Risk != "multiple_nat_configured" {
			t.Errorf("risk = %q, want multiple_nat_configured; reason: %s", rep.Risk, rep.Reason)
		}
		if !strings.Contains(rep.Reason, "egress path") {
			t.Errorf("reason %q should say the devices are not on the same egress path", rep.Reason)
		}
	})

	t.Run("opnsense alone with disabled mode is no risk", func(t *testing.T) {
		op := opnsenseNatModeServer(t, "disabled", false)
		rep, err := NewTopologyService().Report(context.Background(), TopologyOptions{
			Opnsense: opnsenseOpts(op),
		})
		if err != nil {
			t.Fatalf("Report: %v", err)
		}
		if rep.Risk != "none" {
			t.Errorf("risk = %q, want none", rep.Risk)
		}
		if rep.Omada != nil {
			t.Errorf("omada facts = %+v, want nil", rep.Omada)
		}
	})

	t.Run("no provider configured is an error", func(t *testing.T) {
		_, err := NewTopologyService().Report(context.Background(), TopologyOptions{})
		if err == nil || !strings.Contains(err.Error(), "at least one provider") {
			t.Errorf("err = %v, want provider-required error", err)
		}
	})

	t.Run("addrsOverlap is IP-canonical and never guesses", func(t *testing.T) {
		if !addrsOverlap([]string{"10.0.0.254"}, []string{"10.0.0.254"}) {
			t.Error("identical addresses should overlap")
		}
		if addrsOverlap([]string{"10.0.0.254"}, []string{"203.0.113.254"}) {
			t.Error("distinct addresses should not overlap")
		}
		if addrsOverlap(nil, []string{"10.0.0.254"}) || addrsOverlap([]string{"10.0.0.254"}, nil) {
			t.Error("empty side should not overlap")
		}
		if addrsOverlap([]string{"not-an-ip"}, []string{"10.0.0.254"}) {
			t.Error("unparseable addresses should not overlap")
		}
	})

	t.Run("interfaces read failure is best-effort", func(t *testing.T) {
		// Path membership cannot be proven, so two NAT-configured
		// devices stay a conservative double_nat — the report must
		// still succeed.
		om := omadaGatewayServer(t)
		op := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/firewall/source_nat/get":
				testutil.WriteBody(w, testutil.SNATModeBody("automatic"))
			case "/api/firewall/d_nat/search_rule",
				"/api/firewall/one_to_one/search_rule",
				"/api/firewall/source_nat/search_rule":
				testutil.WriteBody(w, `{"total":0,"rows":[]}`)
			case "/api/interfaces/overview/interfaces_info":
				w.WriteHeader(http.StatusNotFound)
			default:
				t.Errorf("unexpected opnsense path %s", r.URL.Path)
				w.WriteHeader(http.StatusNotFound)
			}
		})
		rep, err := NewTopologyService().Report(context.Background(), TopologyOptions{
			Omada:    omadaOpts(om),
			Opnsense: opnsenseOpts(op),
		})
		if err != nil {
			t.Fatalf("Report: %v", err)
		}
		if rep.Risk != "double_nat" {
			t.Errorf("risk = %q, want conservative double_nat; reason: %s", rep.Risk, rep.Reason)
		}
	})

	t.Run("fetch failure is a hard error", func(t *testing.T) {
		om := omadaGatewayServer(t)
		op := opnsenseNatModeServer(t, "disabled", true)
		_, err := NewTopologyService().Report(context.Background(), TopologyOptions{
			Omada:    omadaOpts(om),
			Opnsense: opnsenseOpts(op),
		})
		if err == nil {
			t.Fatal("expected opnsense fetch failure to propagate")
		}
		if !strings.Contains(err.Error(), "observing opnsense") {
			t.Errorf("err = %v, want observing-opnsense prefix", err)
		}
	})
}
