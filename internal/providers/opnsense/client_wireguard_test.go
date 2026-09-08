package opnsense

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
)

func TestGetWireGuardObserve(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "search_server"):
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"s1","name":"home-wg","enabled":"1","tunneladdress":"10.0.90.1/24","listenport":"51820","peers":"p1,p2"}]}`)
		case strings.Contains(r.URL.Path, "search_client"):
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"p1","name":"laptop","enabled":true,"pubkey":"pub1","tunneladdress":"10.0.90.2/32","server":"s1","allowedips":"10.0.0.0/8","privkey":"IGNORE-ME"}]}`)
		case strings.Contains(r.URL.Path, "service/status"):
			testutil.WriteBody(w, `{"running":true}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	servers, err := c.GetWireGuardServers(context.Background())
	if err != nil || len(servers) != 1 || servers[0].Name != "home-wg" || servers[0].ListenPort != 51820 || !servers[0].Enabled {
		t.Fatalf("servers = %+v, %v", servers, err)
	}
	if got := strings.Join(servers[0].Peers, ","); got != "p1,p2" {
		t.Fatalf("peers = %q", got)
	}
	clients, err := c.GetWireGuardClients(context.Background())
	if err != nil || len(clients) != 1 || clients[0].Pubkey != "pub1" || clients[0].TunnelAddress != "10.0.90.2/32" {
		t.Fatalf("clients = %+v, %v", clients, err)
	}
	st, err := c.GetWireGuardStatus(context.Background())
	if err != nil || st == nil || !st.Running {
		t.Fatalf("status = %+v, %v", st, err)
	}
}

func TestGetWireGuard_403(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	if _, err := c.GetWireGuardServers(context.Background()); err == nil || !isPermissionDenied(err) {
		t.Errorf("servers 403 = %v", err)
	}
	if _, err := c.GetWireGuardClients(context.Background()); err == nil || !isPermissionDenied(err) {
		t.Errorf("clients 403 = %v", err)
	}
	if _, err := c.GetWireGuardStatus(context.Background()); err == nil {
		t.Error("status 403 expected error")
	}
}

func TestGetWireGuardSkipBadRowsAnd404(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "search_server"):
			testutil.WriteBody(w, `{"total":2,"rows":["x",{"uuid":""},{"uuid":"ok","descr":"wg","enabled":1,"listen_port":"51821"}]}`)
		case strings.Contains(r.URL.Path, "search_client"):
			testutil.WriteBody(w, `{"total":2,"rows":["x",{"uuid":""},{"uuid":"c2","publickey":"pk","allowed_ips":"10.0.10.0/24"}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	servers, err := c.GetWireGuardServers(context.Background())
	if err != nil || len(servers) != 1 || servers[0].UUID != "ok" || servers[0].ListenPort != 51821 {
		t.Fatalf("servers = %+v, %v", servers, err)
	}
	clients, err := c.GetWireGuardClients(context.Background())
	if err != nil || len(clients) != 1 || clients[0].Pubkey != "pk" {
		t.Fatalf("clients = %+v, %v", clients, err)
	}
	if _, err := c.GetWireGuardStatus(context.Background()); err == nil {
		t.Fatal("expected status 404")
	}
}

func TestDecodeLooseIntAndStringList(t *testing.T) {
	if got := decodeLooseInt(nil, json.RawMessage(`" 7 "`), json.RawMessage(`9`)); got != 7 {
		t.Fatalf("int = %d, want 7", got)
	}
	if got := decodeLooseInt(json.RawMessage(`"nope"`), json.RawMessage(`[]`)); got != 0 {
		t.Fatalf("bad int = %d", got)
	}
	if got := decodeStringList(json.RawMessage(`["a","b"]`)); strings.Join(got, ",") != "a,b" {
		t.Fatalf("list = %v", got)
	}
	if got := decodeStringList(json.RawMessage(`{"p1":{"selected":1},"p2":{"selected":0}}`)); len(got) != 1 || got[0] != "p1" {
		t.Fatalf("selected = %v", got)
	}
	if got := decodeStringList(nil); got != nil {
		t.Fatalf("nil list = %v", got)
	}
}

func TestGetWireGuardStatusShapes(t *testing.T) {
	t.Run("status string", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `{"wireguard":"running"}`)
		}))
		st, err := c.GetWireGuardStatus(context.Background())
		if err != nil || st == nil || !st.Running {
			t.Fatalf("got %+v %v", st, err)
		}
	})
	t.Run("stopped", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `{"running":false}`)
		}))
		st, err := c.GetWireGuardStatus(context.Background())
		if err != nil || st == nil || st.Running {
			t.Fatalf("got %+v %v", st, err)
		}
	})
	t.Run("bad json", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `not json`)
		}))
		if _, err := c.GetWireGuardStatus(context.Background()); err == nil || !strings.Contains(err.Error(), "decoding wireguard service status") {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestFetchInventoryWireGuardDegrades(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/interfaces/overview/interfaces_info":
			testutil.WriteBody(w, `{"interfaces":{"lan":{"description":"LAN","ipv4":"10.0.10.1/24"}}}`)
		case "/api/wireguard/server/search_server", "/api/wireguard/client/search_client", "/api/wireguard/service/status":
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	snap, err := c.FetchInventory(context.Background())
	if err != nil {
		t.Fatalf("FetchInventory: %v", err)
	}
	if snap.WireGuardOK {
		t.Fatal("WireGuardOK should be false on 403")
	}
	joined := strings.Join(snap.Warnings, " ")
	if !strings.Contains(joined, "wireguard") {
		t.Fatalf("warnings = %v", snap.Warnings)
	}
}

func TestFetchInventoryWireGuard404Silent(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/interfaces/overview/interfaces_info":
			testutil.WriteBody(w, `{"interfaces":{"lan":{"description":"LAN","ipv4":"10.0.10.1/24"}}}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	snap, err := c.FetchInventory(context.Background())
	if err != nil {
		t.Fatalf("FetchInventory: %v", err)
	}
	for _, w := range snap.Warnings {
		if strings.Contains(w, "wireguard") {
			t.Fatalf("404 plugin-absent must be silent, got %q", w)
		}
	}
}

func TestFetchInventoryWireGuardPartialDegrade(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "interfaces_info"):
			testutil.WriteBody(w, `{"interfaces":{"lan":{"description":"LAN","ipv4":"10.0.10.1/24"}}}`)
		case strings.Contains(r.URL.Path, "search_server"):
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"s1","name":"home-wg"}]}`)
		case strings.Contains(r.URL.Path, "search_client"):
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	snap, err := c.FetchInventory(context.Background())
	if err != nil {
		t.Fatalf("FetchInventory: %v", err)
	}
	if snap.WireGuardOK {
		t.Fatal("partial 403 must not mark WireGuardOK")
	}
	if !strings.Contains(strings.Join(snap.Warnings, " "), "wireguard clients") {
		t.Fatalf("warnings = %v", snap.Warnings)
	}
}

func TestFetchInventoryWireGuardStatusDegrade(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "interfaces_info"):
			testutil.WriteBody(w, `{"interfaces":{"lan":{"description":"LAN","ipv4":"10.0.10.1/24"}}}`)
		case strings.Contains(r.URL.Path, "search_server"):
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"s1"}]}`)
		case strings.Contains(r.URL.Path, "search_client"):
			testutil.WriteBody(w, `{"total":0,"rows":[]}`)
		case strings.Contains(r.URL.Path, "service/status"):
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	snap, err := c.FetchInventory(context.Background())
	if err != nil {
		t.Fatalf("FetchInventory: %v", err)
	}
	if snap.WireGuardOK {
		t.Fatal("status 403 must not mark WireGuardOK")
	}
	if !strings.Contains(strings.Join(snap.Warnings, " "), "wireguard status") {
		t.Fatalf("warnings = %v", snap.Warnings)
	}
}

func TestRenderInventoryWireGuardOff(t *testing.T) {
	snap := &InventorySnapshot{
		Interfaces:       []Interface{{Name: "lan", IP: "10.0.10.1", Subnet: 24}},
		WireGuardServers: []WireGuardServer{{UUID: "s1"}, {UUID: "s2"}},
		WireGuardStatus:  &WireGuardStatus{Running: false},
		WireGuardOK:      true,
	}
	out := RenderInventory(snap, "opnsense-firewall")
	if !strings.Contains(out, "off, 2 servers, 0 peers") {
		t.Fatalf("render = %s", out)
	}
}
