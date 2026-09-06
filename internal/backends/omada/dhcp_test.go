package omada

import (
	"context"
	"net/http"
	"testing"
)

func TestGetDHCPServerInfo(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/openapi/v1/abc123/sites/s1/networks/n1/dhcp-server-info" {
			t.Errorf("path = %s", r.URL.Path)
		}
		writeEnvelope(w, 0, "", `{"availableIpCount":12,"totalIpCount":180,"ipaddrStart":"10.0.10.20","ipaddrEnd":"10.0.10.200"}`)
	}))
	info, err := c.GetDHCPServerInfo(context.Background(), "s1", "n1")
	if err != nil {
		t.Fatalf("GetDHCPServerInfo: %v", err)
	}
	if info.AvailableIPs != 12 || info.TotalIPs != 180 || info.Start != "10.0.10.20" {
		t.Fatalf("info = %+v", info)
	}
}

func TestGetDHCPSnoopStatusAndRules(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/v1/abc123/sites/s1/dhcpSnoops/status":
			writeEnvelope(w, 0, "", `{"enable":true}`)
		case "/openapi/v1/abc123/sites/s1/dhcpSnoops":
			writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"r1","name":"trust-ports","enabled":true}]}`)
		default:
			t.Errorf("path = %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	st, err := c.GetDHCPSnoopStatus(context.Background(), "s1")
	if err != nil || st == nil || !st.Enabled {
		t.Fatalf("status = %+v err=%v", st, err)
	}
	rules, err := c.GetDHCPSnoops(context.Background(), "s1")
	if err != nil || len(rules) != 1 || rules[0].Name != "trust-ports" || !rules[0].Enabled {
		t.Fatalf("rules = %+v err=%v", rules, err)
	}
}

func TestDHCPReads_Errors(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, -1, "boom", "null")
	}))
	if _, err := c.GetDHCPServerInfo(context.Background(), "s1", "n1"); err == nil {
		t.Fatal("expected server-info error")
	}
	if _, err := c.GetDHCPSnoopStatus(context.Background(), "s1"); err == nil {
		t.Fatal("expected snoop-status error")
	}
	if _, err := c.GetDHCPSnoops(context.Background(), "s1"); err == nil {
		t.Fatal("expected snoop-rules error")
	}
	if _, err := c.GetLANMulticasts(context.Background(), "s1"); err == nil {
		t.Fatal("expected multicast error")
	}
}

func TestGetLANMulticasts(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/openapi/v1/abc123/sites/s1/lan-multicasts" {
			t.Errorf("path = %s", r.URL.Path)
		}
		writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"m1","name":"drop-ssdp","status":true}]}`)
	}))
	rows, err := c.GetLANMulticasts(context.Background(), "s1")
	if err != nil || len(rows) != 1 || rows[0].Name != "drop-ssdp" || !rows[0].Enabled {
		t.Fatalf("rows = %+v err=%v", rows, err)
	}
}
