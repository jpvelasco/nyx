package opnsense

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
)

func TestGetBridgeSettings(t *testing.T) {
	t.Run("rows", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/interfaces/bridge_settings/search_item" {
				t.Errorf("path = %s", r.URL.Path)
			}
			testutil.WriteBody(w, `{"total":1,"rows":[
				{"uuid":"b1","descr":"lan-bridge","members":"igb0,igb1","stp":"1"}
			]}`)
		}))
		got, err := c.GetBridgeSettings(context.Background())
		if err != nil {
			t.Fatalf("GetBridgeSettings: %v", err)
		}
		if len(got) != 1 || got[0].UUID != "b1" || got[0].Description != "lan-bridge" || len(got[0].Members) != 2 || !got[0].STP {
			t.Fatalf("bridges = %+v", got)
		}
	})
	t.Run("403", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		_, err := c.GetBridgeSettings(context.Background())
		if err == nil || !isPermissionDenied(err) {
			t.Errorf("error = %v, want permission-denied", err)
		}
	})
	t.Run("skips malformed", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `{"total":2,"rows":["x",{"uuid":"","members":"igb0"},{"uuid":"ok","description":"br"}]}`)
		}))
		got, err := c.GetBridgeSettings(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].UUID != "ok" {
			t.Fatalf("got %+v", got)
		}
	})
}

func TestGetInterfaceSettings(t *testing.T) {
	t.Run("map", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/interfaces/settings/get" {
				t.Errorf("path = %s", r.URL.Path)
			}
			testutil.WriteBody(w, `{"interface":{"lan":{"enable":"1","if":"bridge0","descr":"LAN","ipaddr":"10.0.10.1","subnet":"24"},"wan":{"enable":"0","if":"igb0"}}}`)
		}))
		got, err := c.GetInterfaceSettings(context.Background())
		if err != nil {
			t.Fatalf("GetInterfaceSettings: %v", err)
		}
		byName := map[string]InterfaceSetting{}
		for _, s := range got {
			byName[s.Name] = s
		}
		if !byName["lan"].Enabled || byName["lan"].Device != "bridge0" || byName["lan"].IPv4 != "10.0.10.1" {
			t.Fatalf("lan = %+v", byName["lan"])
		}
		if byName["wan"].Enabled {
			t.Fatalf("wan should be disabled: %+v", byName["wan"])
		}
	})
	t.Run("403", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		_, err := c.GetInterfaceSettings(context.Background())
		if err == nil || !isPermissionDenied(err) {
			t.Errorf("error = %v, want permission-denied", err)
		}
	})
	t.Run("bad json", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `not json`)
		}))
		_, err := c.GetInterfaceSettings(context.Background())
		if err == nil || !strings.Contains(err.Error(), "decoding interface settings") {
			t.Errorf("error = %v", err)
		}
	})
}

func TestGetDnsmasqSettings(t *testing.T) {
	t.Run("ranges and hosts", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/dnsmasq/settings/get" {
				t.Errorf("path = %s", r.URL.Path)
			}
			testutil.WriteBody(w, `{"dnsmasq":{"enable":"1","interface":{"lan":{"selected":1},"wan":{"selected":0}},"dhcp":{"range":{"r1":{"interface":"lan","start":"10.0.10.100","end":"10.0.10.200"}},"host":{"h1":{"host":"printer","ip":"10.0.10.20"}}}}}`)
		}))
		got, err := c.GetDnsmasqSettings(context.Background())
		if err != nil {
			t.Fatalf("GetDnsmasqSettings: %v", err)
		}
		if !got.Enabled || len(got.Interfaces) != 1 || got.Interfaces[0] != "lan" {
			t.Fatalf("settings = %+v", got)
		}
		if len(got.Ranges) != 1 || got.Ranges[0].Start != "10.0.10.100" || got.Ranges[0].End != "10.0.10.200" {
			t.Fatalf("ranges = %+v", got.Ranges)
		}
		if len(got.Hosts) != 1 || got.Hosts[0].Host != "printer" || got.Hosts[0].IP != "10.0.10.20" {
			t.Fatalf("hosts = %+v", got.Hosts)
		}
	})
	t.Run("403", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		_, err := c.GetDnsmasqSettings(context.Background())
		if err == nil || !isPermissionDenied(err) {
			t.Errorf("error = %v, want permission-denied", err)
		}
	})
}

func TestGetPfStatistics(t *testing.T) {
	t.Run("nested states", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/diagnostics/firewall/pf_statistics" {
				t.Errorf("path = %s", r.URL.Path)
			}
			testutil.WriteBody(w, `{"states":{"current":42,"limit":100000},"info":{"source_count":3}}`)
		}))
		got, err := c.GetPfStatistics(context.Background())
		if err != nil {
			t.Fatalf("GetPfStatistics: %v", err)
		}
		if got.StateCount != 42 || got.Limit != 100000 || got.SourceCount != 3 {
			t.Fatalf("stats = %+v", got)
		}
	})
	t.Run("403", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		_, err := c.GetPfStatistics(context.Background())
		if err == nil || !isPermissionDenied(err) {
			t.Errorf("error = %v, want permission-denied", err)
		}
	})
}

func TestGetKernelRoutes(t *testing.T) {
	t.Run("rows", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/diagnostics/interface/get_routes" {
				t.Errorf("path = %s", r.URL.Path)
			}
			testutil.WriteBody(w, `{"rows":[{"destination":"default","gateway":"203.0.113.1","netif":"igb0","flags":"UGS"}]}`)
		}))
		got, err := c.GetKernelRoutes(context.Background())
		if err != nil {
			t.Fatalf("GetKernelRoutes: %v", err)
		}
		if len(got) != 1 || got[0].Destination != "default" || got[0].Gateway != "203.0.113.1" {
			t.Fatalf("routes = %+v", got)
		}
	})
	t.Run("routes envelope", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `{"routes":[{"destination":"10.0.10.0/24","netif":"bridge0"}]}`)
		}))
		got, err := c.GetKernelRoutes(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 || got[0].Destination != "10.0.10.0/24" {
			t.Fatalf("routes = %+v", got)
		}
	})
	t.Run("403", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		_, err := c.GetKernelRoutes(context.Background())
		if err == nil || !isPermissionDenied(err) {
			t.Errorf("error = %v, want permission-denied", err)
		}
	})
}

func TestParseInterfaceSettings_EmptyAndLegacyKey(t *testing.T) {
	got, err := parseInterfaceSettings([]byte(`{"interfaces":{"opt1":{"enable":"true","if":"igb2","descr":"OPT"}}}`))
	if err != nil || len(got) != 1 || got[0].Name != "opt1" || !got[0].Enabled {
		t.Fatalf("legacy key = %+v, %v", got, err)
	}
	got, err = parseInterfaceSettings([]byte(`{}`))
	if err != nil || len(got) != 0 {
		t.Fatalf("empty = %+v, %v", got, err)
	}
	if _, err := parseInterfaceSettings([]byte(`{"interface":[]}`)); err == nil {
		t.Fatal("want decode error for array interface blob")
	}
}

func TestParseDnsmasqSettings_HostsFallbackAndSkip(t *testing.T) {
	got, err := parseDnsmasqSettings([]byte(`{"enable":"0","hosts":{"h2":{"host":"cam","ip":"10.0.60.8"},"bad":{"host":""}}}`))
	if err != nil || got.Enabled || len(got.Hosts) != 1 || got.Hosts[0].Host != "cam" {
		t.Fatalf("hosts fallback = %+v, %v", got, err)
	}
	if _, err := parseDnsmasqSettings([]byte(`not json`)); err == nil {
		t.Fatal("want decode error")
	}
}

func TestParsePfAndRoutes_BadJSON(t *testing.T) {
	if _, err := parsePfStatistics([]byte(`not json`)); err == nil {
		t.Fatal("want pf decode error")
	}
	if _, err := parseKernelRoutes([]byte(`not json`)); err == nil {
		t.Fatal("want routes decode error")
	}
	got, err := parseKernelRoutes([]byte(`{}`))
	if err != nil || got != nil {
		t.Fatalf("empty routes = %+v, %v", got, err)
	}
}

func TestGetRecon_DecodeErrors(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testutil.WriteBody(w, `not json`)
	}))
	if _, err := c.GetDnsmasqSettings(context.Background()); err == nil || !strings.Contains(err.Error(), "decoding dnsmasq") {
		t.Errorf("dnsmasq: %v", err)
	}
	if _, err := c.GetPfStatistics(context.Background()); err == nil || !strings.Contains(err.Error(), "decoding pf") {
		t.Errorf("pf: %v", err)
	}
	if _, err := c.GetKernelRoutes(context.Background()); err == nil || !strings.Contains(err.Error(), "decoding kernel") {
		t.Errorf("routes: %v", err)
	}
}

func TestParseHelpers(t *testing.T) {
	if firstNonZero(0, 0, 7, 1) != 7 {
		t.Error("firstNonZero")
	}
	if got := selectedKeys(nil); got != nil {
		t.Errorf("nil selected = %v", got)
	}
	if got := selectedKeys([]byte(`"lan,wan"`)); len(got) != 2 {
		t.Errorf("csv selected = %v", got)
	}
}
