package opnsense

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
)

func TestDetectDHCPBackend(t *testing.T) {
	t.Run("dnsmasq", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "dnsmasq/settings/get"):
				testutil.WriteBody(w, `{"dnsmasq":{"enable":"1"}}`)
			case strings.Contains(r.URL.Path, "kea/service/status"):
				testutil.WriteBody(w, `{"running":false}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		got, err := c.DetectDHCPBackend(context.Background())
		if err != nil || got != "dnsmasq" {
			t.Fatalf("got %q %v", got, err)
		}
	})
	t.Run("kea", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "dnsmasq/settings/get"):
				testutil.WriteBody(w, `{"dnsmasq":{"enable":"0"}}`)
			case strings.Contains(r.URL.Path, "kea/service/status"):
				testutil.WriteBody(w, `{"running":true}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		got, err := c.DetectDHCPBackend(context.Background())
		if err != nil || got != "kea" {
			t.Fatalf("got %q %v", got, err)
		}
	})
	t.Run("none", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.Contains(r.URL.Path, "dnsmasq/settings/get"):
				testutil.WriteBody(w, `{"dnsmasq":{"enable":"0"}}`)
			case strings.Contains(r.URL.Path, "kea/service/status"):
				testutil.WriteBody(w, `{"running":false}`)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		if _, err := c.DetectDHCPBackend(context.Background()); err == nil || !strings.Contains(err.Error(), "no running DHCP backend") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestDHCPWriteCRUD(t *testing.T) {
	var seen []string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		testutil.WriteBody(w, `{"uuid":"new1","result":"saved"}`)
	}))
	if id, err := c.CreateDnsmasqRange(context.Background(), DnsmasqRangeWrite{Interface: "lan", Start: "10.0.10.100", End: "10.0.10.200"}); err != nil || id == "" {
		t.Fatalf("create range = %q %v", id, err)
	}
	if err := c.SetDnsmasqRange(context.Background(), "r1", DnsmasqRangeWrite{Interface: "lan", Start: "10.0.10.100", End: "10.0.10.210"}); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteDnsmasqRange(context.Background(), "r1"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateDnsmasqHost(context.Background(), DnsmasqHostWrite{Host: "printer", IP: "10.0.10.20"}); err != nil {
		t.Fatal(err)
	}
	if err := c.SetDnsmasqHost(context.Background(), "h1", DnsmasqHostWrite{Host: "printer", IP: "10.0.10.21"}); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteDnsmasqHost(context.Background(), "h1"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateKeaSubnet(context.Background(), KeaSubnetWrite{Subnet: "10.0.10.0/24"}); err != nil {
		t.Fatal(err)
	}
	if err := c.SetKeaSubnet(context.Background(), "s1", KeaSubnetWrite{Subnet: "10.0.10.0/24"}); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteKeaSubnet(context.Background(), "s1"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.CreateKeaReservation(context.Background(), KeaReservationWrite{IP: "10.0.10.20", MAC: "aa:bb:cc:dd:ee:01"}); err != nil {
		t.Fatal(err)
	}
	if err := c.SetKeaReservation(context.Background(), "k1", KeaReservationWrite{IP: "10.0.10.20", MAC: "aa:bb:cc:dd:ee:01"}); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteKeaReservation(context.Background(), "k1"); err != nil {
		t.Fatal(err)
	}
	if err := c.ReconfigureDnsmasq(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.ReconfigureKea(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(seen) < 12 {
		t.Fatalf("seen = %v", seen)
	}
}

func TestFindDHCPRows(t *testing.T) {
	ranges := []DnsmasqRange{{UUID: "r1", Interface: "lan", Start: "10.0.10.100", End: "10.0.10.200"}}
	if _, ok := FindDnsmasqRange(ranges, "r1", "", "", ""); !ok {
		t.Fatal("uuid miss")
	}
	if _, ok := FindDnsmasqRange(ranges, "", "lan", "10.0.10.100", "10.0.10.200"); !ok {
		t.Fatal("tuple miss")
	}
	hosts := []DnsmasqHost{{UUID: "h1", Host: "printer", IP: "10.0.10.20"}}
	if _, ok := FindDnsmasqHost(hosts, "", "printer", "10.0.10.20"); !ok {
		t.Fatal("host miss")
	}
	subs := []KeaSubnet{{UUID: "s1", Subnet: "10.0.10.0/24"}}
	if _, ok := FindKeaSubnet(subs, "", "10.0.10.0/24"); !ok {
		t.Fatal("subnet miss")
	}
	res := []KeaReservation{{UUID: "k1", IP: "10.0.10.20", MAC: "aa:bb:cc:dd:ee:01"}}
	if _, ok := FindKeaReservation(res, "", "10.0.10.20", "aa:bb:cc:dd:ee:01"); !ok {
		t.Fatal("resv miss")
	}
}
