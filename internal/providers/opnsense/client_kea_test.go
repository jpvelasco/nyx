package opnsense

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
)

func TestGetDHCPLeases_KeaFallback(t *testing.T) {
	var seen []string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Path)
		switch r.URL.Path {
		case "/api/dnsmasq/leases/search":
			w.WriteHeader(http.StatusNotFound)
		case "/api/kea/leases/search":
			testutil.WriteBody(w, `{"leases":[{"mac":"aa:bb:cc:dd:ee:01","ip":"10.0.10.20","hostname":"pc1"}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	leases, err := c.GetDHCPLeases(context.Background())
	if err != nil {
		t.Fatalf("GetDHCPLeases: %v", err)
	}
	if len(leases) != 1 || leases[0].IP != "10.0.10.20" {
		t.Fatalf("leases = %+v", leases)
	}
	if strings.Join(seen, ",") != "/api/dnsmasq/leases/search,/api/kea/leases/search" {
		t.Errorf("probe order = %v", seen)
	}
}

func TestGetKeaSubnetsAndReservations(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "search_subnet"):
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"s1","subnet":"10.0.10.0/24","description":"trusted"}]}`)
		case strings.Contains(r.URL.Path, "search_reservation"):
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"r1","ip_address":"10.0.10.20","hw_address":"aa:bb:cc:dd:ee:01","hostname":"printer"}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	subs, err := c.GetKeaSubnets(context.Background())
	if err != nil || len(subs) != 1 || subs[0].Subnet != "10.0.10.0/24" {
		t.Fatalf("subnets = %+v, %v", subs, err)
	}
	res, err := c.GetKeaReservations(context.Background())
	if err != nil || len(res) != 1 || res[0].IP != "10.0.10.20" || res[0].MAC != "aa:bb:cc:dd:ee:01" {
		t.Fatalf("reservations = %+v, %v", res, err)
	}
}

func TestGetKea_403(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	if _, err := c.GetKeaSubnets(context.Background()); err == nil || !isPermissionDenied(err) {
		t.Errorf("subnets 403 = %v", err)
	}
	if _, err := c.GetKeaReservations(context.Background()); err == nil || !isPermissionDenied(err) {
		t.Errorf("resv 403 = %v", err)
	}
}

func TestGetKeaServiceStatus(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testutil.WriteBody(w, `{"running":true}`)
	}))
	ok, err := c.GetKeaServiceStatus(context.Background())
	if err != nil || !ok {
		t.Fatalf("status = %v, %v", ok, err)
	}
}

func TestGetKeaSubnetsAndReservations_SkipBadRows(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "search_subnet"):
			testutil.WriteBody(w, `{"total":2,"rows":["x",{"uuid":""},{"uuid":"ok","subnet":"10.0.10.0/24"}]}`)
		case strings.Contains(r.URL.Path, "search_reservation"):
			testutil.WriteBody(w, `{"total":2,"rows":["x",{"uuid":""},{"uuid":"r2","ip":"10.0.10.9","mac":"aa:bb:cc:dd:ee:09"}]}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	subs, err := c.GetKeaSubnets(context.Background())
	if err != nil || len(subs) != 1 || subs[0].UUID != "ok" {
		t.Fatalf("subnets = %+v, %v", subs, err)
	}
	res, err := c.GetKeaReservations(context.Background())
	if err != nil || len(res) != 1 || res[0].IP != "10.0.10.9" || res[0].MAC != "aa:bb:cc:dd:ee:09" {
		t.Fatalf("reservations = %+v, %v", res, err)
	}
}

func TestGetKeaServiceStatus_Shapes(t *testing.T) {
	t.Run("status string", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `{"kea":"running"}`)
		}))
		ok, err := c.GetKeaServiceStatus(context.Background())
		if err != nil || !ok {
			t.Fatalf("got %v %v", ok, err)
		}
	})
	t.Run("ok string", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `{"status":"OK"}`)
		}))
		ok, err := c.GetKeaServiceStatus(context.Background())
		if err != nil || !ok {
			t.Fatalf("got %v %v", ok, err)
		}
	})
	t.Run("stopped", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `{"running":false}`)
		}))
		ok, err := c.GetKeaServiceStatus(context.Background())
		if err != nil || ok {
			t.Fatalf("got %v %v", ok, err)
		}
	})
	t.Run("bad json", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `not json`)
		}))
		if _, err := c.GetKeaServiceStatus(context.Background()); err == nil || !strings.Contains(err.Error(), "decoding kea service status") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("404", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		if _, err := c.GetKeaServiceStatus(context.Background()); err == nil {
			t.Fatal("expected 404")
		}
	})
}
