package omada

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// Omada NAT + firewall-config reads (BDD omada-nat-firewall reads phase).
// Wire shapes come from the official Open API spec (04-site-setting.json).

func TestGetPortForwardings(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/openapi/v1/abc123/sites/s1/nat/port-forwardings" {
				t.Errorf("path = %q, want sites/s1/nat/port-forwardings", r.URL.Path)
			}
			writeEnvelope(w, 0, "", `{"totalRows":2,"currentPage":1,"currentSize":200,"data":[
				{"id":"pf1","site id":"s1","name":"web-iot","status":true,"from":0,"interfaceWanPortId":["w1"],"wanIps":[{"wanId":"w1","ip":"203.0.113.1"}],"externalPort":"443","forwardIp":"10.0.60.10","forwardPort":"80","protocol":1,"dMZ":false},
				{"id":"pf2","site id":"s1","name":"dns-limited","status":false,"from":1,"limitedAddresses":["10.0.0.5"],"externalPort":"53","forwardIp":"10.0.10.2","forwardPort":"53","protocol":2}
			],"supportWanIp":true}`)
		}))
		pfs, err := c.GetPortForwardings(context.Background(), "s1")
		if err != nil {
			t.Fatalf("GetPortForwardings: %v", err)
		}
		if len(pfs) != 2 {
			t.Fatalf("port forwardings = %+v, want 2", pfs)
		}
		p0 := pfs[0]
		if p0.ID != "pf1" || p0.Name != "web-iot" || !p0.Enabled || p0.From != 0 {
			t.Errorf("pf[0] = %+v", p0)
		}
		if p0.ExternalPort != "443" || p0.ForwardIP != "10.0.60.10" || p0.ForwardPort != "80" {
			t.Errorf("pf[0] ports = %+v", p0)
		}
		if p0.Protocol != "TCP" {
			t.Errorf("pf[0] protocol = %q, want TCP", p0.Protocol)
		}
		p1 := pfs[1]
		if p1.Enabled || p1.From != 1 || len(p1.LimitedAddresses) != 1 || p1.LimitedAddresses[0] != "10.0.0.5" {
			t.Errorf("pf[1] = %+v", p1)
		}
		if p1.Protocol != "UDP" {
			t.Errorf("pf[1] protocol = %q, want UDP", p1.Protocol)
		}
	})

	t.Run("empty", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeEnvelope(w, 0, "", `{"totalRows":0,"data":[]}`)
		}))
		pfs, err := c.GetPortForwardings(context.Background(), "s1")
		if err != nil {
			t.Fatalf("GetPortForwardings: %v", err)
		}
		if len(pfs) != 0 {
			t.Errorf("port forwardings = %+v, want none", pfs)
		}
	})

	t.Run("error envelope", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeEnvelope(w, 57, "permission denied", `null`)
		}))
		_, err := c.GetPortForwardings(context.Background(), "s1")
		if err == nil || !strings.Contains(err.Error(), "port-forwardings") {
			t.Errorf("error = %v, want a port-forwardings fetch error", err)
		}
	})

	t.Run("bad json", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeEnvelope(w, 0, "", `"not-list-shaped"`)
		}))
		_, err := c.GetPortForwardings(context.Background(), "s1")
		if err == nil || !strings.Contains(err.Error(), "decoding paged list response") {
			t.Errorf("error = %v, want decoding paged list response", err)
		}
	})
}

func TestGetOneToOneNAT(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/openapi/v1/abc123/sites/s1/nat/one-to-one-nat" {
				t.Errorf("path = %q, want sites/s1/nat/one-to-one-nat", r.URL.Path)
			}
			writeEnvelope(w, 0, "", `{"totalRows":1,"data":[
				{"id":"o1","name":"nas","status":true,"interfaceIds":["w1"],"internalIp":"10.0.40.10","externalIp":"203.0.113.10","dmz":true,"description":"nas passthrough"}
			]}`)
		}))
		rules, err := c.GetOneToOneNAT(context.Background(), "s1")
		if err != nil {
			t.Fatalf("GetOneToOneNAT: %v", err)
		}
		if len(rules) != 1 {
			t.Fatalf("rules = %+v, want 1", rules)
		}
		r := rules[0]
		if r.ID != "o1" || r.Name != "nas" || !r.Enabled || !r.DMZ {
			t.Errorf("rule = %+v", r)
		}
		if r.InternalIP != "10.0.40.10" || r.ExternalIP != "203.0.113.10" || r.Description != "nas passthrough" {
			t.Errorf("rule ips = %+v", r)
		}
	})

	t.Run("bad json", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeEnvelope(w, 0, "", `"not-list-shaped"`)
		}))
		_, err := c.GetOneToOneNAT(context.Background(), "s1")
		if err == nil || !strings.Contains(err.Error(), "decoding paged list response") {
			t.Errorf("error = %v, want decoding paged list response", err)
		}
	})
}

func TestGetALG(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/openapi/v1/abc123/sites/s1/nat/alg" {
				t.Errorf("path = %q, want sites/s1/nat/alg", r.URL.Path)
			}
			writeEnvelope(w, 0, "", `{"ftp":true,"h323":false,"pptp":true,"sip":false,"ipSec":true}`)
		}))
		alg, err := c.GetALG(context.Background(), "s1")
		if err != nil {
			t.Fatalf("GetALG: %v", err)
		}
		if !alg.FTP || alg.H323 || !alg.PPTP || alg.SIP || !alg.IPsec {
			t.Errorf("alg = %+v, want ftp/pptp/ipSec on, h323/sip off", alg)
		}
	})

	t.Run("bad json", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeEnvelope(w, 0, "", `123`)
		}))
		_, err := c.GetALG(context.Background(), "s1")
		if err == nil || !strings.Contains(err.Error(), "decoding alg response") {
			t.Errorf("error = %v, want decoding alg response", err)
		}
	})
}

func TestGetFirewallSettings(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/openapi/v1/abc123/sites/s1/firewall" {
				t.Errorf("path = %q, want sites/s1/firewall", r.URL.Path)
			}
			writeEnvelope(w, 0, "", `{"icmp":60,"other":30,"tcpEstablished":21600,"tcpTimeWait":30,"udpOther":30,"udpStream":30,"broadcastPing":false,"receiveRedirects":false,"sendRedirects":false,"synCookies":true}`)
		}))
		fw, err := c.GetFirewallSettings(context.Background(), "s1")
		if err != nil {
			t.Fatalf("GetFirewallSettings: %v", err)
		}
		if fw.ICMP != 60 || fw.TCPEstablished != 21600 || fw.TCPTimeWait != 30 || fw.UDPOther != 30 {
			t.Errorf("timeouts = %+v", fw)
		}
		if fw.BroadcastPing || fw.ReceiveRedirects || fw.SendRedirects || !fw.SynCookies {
			t.Errorf("switches = %+v", fw)
		}
	})

	t.Run("bad json", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeEnvelope(w, 0, "", `123`)
		}))
		_, err := c.GetFirewallSettings(context.Background(), "s1")
		if err == nil || !strings.Contains(err.Error(), "decoding firewall settings response") {
			t.Errorf("error = %v, want decoding firewall settings response", err)
		}
	})
}
