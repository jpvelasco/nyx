package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// natReads is the shared handler for the NAT-observation endpoints NatFacts
// touches. unexpected records any path outside the known set.
func natReads(unexpected *strings.Builder) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/openapi/v1/abc123/sites/s1/networks/devices":
			writeOmadaEnvelope(w, 0, `[
				{"id":"d1","name":"GW-CORE","model":"GW-CORE","type":"gateway","mac":"aa:bb:cc:dd:ee:00","ip":"10.0.0.254"},
				{"id":"d2","name":"SW-2428P","model":"SW-2428P","type":"switch","mac":"aa:bb:cc:dd:ee:01","ip":"10.0.0.253"}]`)
		case "/openapi/v1/abc123/sites/s1/nat/port-forwardings":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[
				{"id":"pf1","name":"web","status":true,"from":0,"externalPort":"443","forwardIp":"10.0.40.10","forwardPort":"443","protocol":1,"dMZ":false}]}`)
		case "/openapi/v1/abc123/sites/s1/nat/one-to-one-nat":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[
				{"id":"o1","name":"nas","status":true,"internalIp":"10.0.40.20","externalIp":"203.0.113.20","dmz":false,"description":"nas passthrough"}]}`)
		case "/openapi/v1/abc123/sites/s1/nat/alg":
			writeOmadaEnvelope(w, 0, `{"ftp":true,"h323":false,"pptp":false,"sip":true,"ipSec":false}`)
		case "/openapi/v1/abc123/sites/s1/firewall":
			writeOmadaEnvelope(w, 0, `{"icmp":30,"other":30,"tcpEstablished":86400,"udpOther":30,"broadcastPing":false,"synCookies":true}`)
		default:
			unexpected.WriteString(r.URL.Path + "\n")
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func omadaNatOptions(ts *httptest.Server) OmadaOptions {
	return OmadaOptions{Host: ts.URL, ClientID: "a", ClientSecret: "b", SkipTLSVerify: true}
}

func TestOmadaServiceNatFacts(t *testing.T) {
	var unexpected strings.Builder
	ts := omadaTestServer(t, natReads(&unexpected))
	facts, err := NewOmadaService().NatFacts(context.Background(), omadaNatOptions(ts))
	if err != nil {
		t.Fatalf("NatFacts: %v", err)
	}
	if got := unexpected.String(); got != "" {
		t.Errorf("unexpected paths: %s", got)
	}
	if facts.Site != "HQ" || !facts.HasManagedGateway {
		t.Errorf("site/gateway = %q/%v, want HQ/true", facts.Site, facts.HasManagedGateway)
	}
	if facts.PortForwardRules != 1 || facts.OneToOneRules != 1 {
		t.Errorf("rule counts = %d/%d, want 1/1", facts.PortForwardRules, facts.OneToOneRules)
	}
	if !facts.ALG.FTP || !facts.ALG.SIP || facts.ALG.H323 || facts.ALG.IPsec {
		t.Errorf("alg = %+v, want ftp+sip only", facts.ALG)
	}
	if facts.Firewall.UDPOther != 30 || facts.Firewall.TCPEstablished != 86400 || !facts.Firewall.SynCookies {
		t.Errorf("firewall = %+v", facts.Firewall)
	}
}

func TestOmadaServiceNatFacts_NoGateway(t *testing.T) {
	var unexpected strings.Builder
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi/v1/abc123/sites/s1/networks/devices" {
			writeOmadaEnvelope(w, 0, `[
				{"id":"d2","name":"SW-2428P","model":"SW-2428P","type":"switch","mac":"aa:bb:cc:dd:ee:01","ip":"10.0.0.253"}]`)
			return
		}
		natReads(&unexpected)(w, r)
	})
	facts, err := NewOmadaService().NatFacts(context.Background(), omadaNatOptions(ts))
	if err != nil {
		t.Fatalf("NatFacts: %v", err)
	}
	if facts.HasManagedGateway {
		t.Error("HasManagedGateway = true, want false for switch-only site")
	}
}

// A partial NAT picture would mislead the double-NAT verdict, so a failure
// on any read must surface as a hard error.
func TestOmadaServiceNatFacts_HardError(t *testing.T) {
	var unexpected strings.Builder
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi/v1/abc123/sites/s1/nat/alg" {
			writeOmadaEnvelope(w, -1010, `null`)
			return
		}
		natReads(&unexpected)(w, r)
	})
	_, err := NewOmadaService().NatFacts(context.Background(), omadaNatOptions(ts))
	if err == nil {
		t.Fatal("expected ALG failure to propagate")
	}
	if !strings.Contains(err.Error(), "fetching ALG settings") {
		t.Errorf("error = %v, want ALG fetch prefix", err)
	}
}

func TestOmadaServiceListPortForwardings(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/openapi/v1/abc123/sites/s1/nat/port-forwardings":
			writeOmadaEnvelope(w, 0, `{"totalRows":2,"data":[
				{"id":"pf1","name":"web","status":true,"from":1,"limitedAddresses":["10.0.10.0/24"],"externalPort":"443","forwardIp":"10.0.40.10","forwardPort":"443","protocol":1,"dMZ":false},
				{"id":"pf2","name":"mail","status":false,"from":0,"externalPort":"25","forwardIp":"10.0.40.11","forwardPort":"25","protocol":0}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	pfs, err := NewOmadaService().ListPortForwardings(context.Background(), omadaNatOptions(ts))
	if err != nil {
		t.Fatalf("ListPortForwardings: %v", err)
	}
	if len(pfs) != 2 {
		t.Fatalf("len = %d, want 2", len(pfs))
	}
	if pfs[0].Protocol != "TCP" || !pfs[0].Enabled || len(pfs[0].LimitedAddresses) != 1 {
		t.Errorf("pf1 = %+v", pfs[0])
	}
	if pfs[1].Protocol != "ALL" || pfs[1].Enabled {
		t.Errorf("pf2 = %+v", pfs[1])
	}
}

func TestOmadaServiceListOneToOneNAT(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/openapi/v1/abc123/sites/s1/nat/one-to-one-nat":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[
				{"id":"o1","name":"nas","status":true,"internalIp":"10.0.40.20","externalIp":"203.0.113.20","dmz":true}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	rules, err := NewOmadaService().ListOneToOneNAT(context.Background(), omadaNatOptions(ts))
	if err != nil {
		t.Fatalf("ListOneToOneNAT: %v", err)
	}
	if len(rules) != 1 || !rules[0].DMZ || rules[0].InternalIP != "10.0.40.20" {
		t.Errorf("rules = %+v", rules)
	}
}

func TestOmadaServiceGetALGAndFirewall(t *testing.T) {
	var unexpected strings.Builder
	ts := omadaTestServer(t, natReads(&unexpected))
	svc := NewOmadaService()

	alg, err := svc.GetALGSettings(context.Background(), omadaNatOptions(ts))
	if err != nil {
		t.Fatalf("GetALGSettings: %v", err)
	}
	if !alg.FTP || !alg.SIP {
		t.Errorf("alg = %+v", alg)
	}

	fw, err := svc.GetFirewallSettings(context.Background(), omadaNatOptions(ts))
	if err != nil {
		t.Fatalf("GetFirewallSettings: %v", err)
	}
	if fw.ICMP != 30 || fw.UDPStream != 0 || !fw.SynCookies {
		t.Errorf("firewall = %+v", fw)
	}
}
