package opnsense

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
)

func TestGetVLANsAndWrites(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "search_item"):
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"v1","if":"igb0","tag":"60","descr":"iot","vlanif":"igb0.60"}]}`)
		case strings.Contains(r.URL.Path, "add_item"):
			testutil.WriteBody(w, `{"result":"saved","uuid":"v-new"}`)
		case strings.Contains(r.URL.Path, "set_item"), strings.Contains(r.URL.Path, "del_item"), strings.Contains(r.URL.Path, "reconfigure"):
			testutil.WriteBody(w, `{"result":"saved"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	rows, err := c.GetVLANs(context.Background())
	if err != nil || len(rows) != 1 || rows[0].Tag != 60 || rows[0].Parent != "igb0" {
		t.Fatalf("GetVLANs = %+v %v", rows, err)
	}
	id, err := c.CreateVLAN(context.Background(), VLANWrite{Parent: "igb0", Tag: 70, Description: "guest"})
	if err != nil || id != "v-new" {
		t.Fatalf("create = %q %v", id, err)
	}
	if err := c.SetVLAN(context.Background(), "v1", VLANWrite{Parent: "igb0", Tag: 60}); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteVLAN(context.Background(), "v1"); err != nil {
		t.Fatal(err)
	}
	if err := c.ReconfigureVLANs(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.SetBridgeMembers(context.Background(), "b1", []string{"igb0", "igb0.60"}, "lan"); err != nil {
		t.Fatal(err)
	}
	if err := c.ReconfigureBridges(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestVLANHelpers(t *testing.T) {
	rows := []VLAN{{UUID: "v1", Parent: "igb0", Tag: 60, Description: "iot"}}
	if got, ok := FindVLAN(rows, "v1", "", 0); !ok || got.Tag != 60 {
		t.Fatal("uuid match")
	}
	if got, ok := FindVLAN(rows, "", "igb0", 60); !ok || got.UUID != "v1" {
		t.Fatal("parent+tag match")
	}
	if _, ok := FindVLAN(rows, "", "igb1", 60); ok {
		t.Fatal("want miss")
	}
	if !VLANMatchesWrite(rows[0], VLANWrite{Parent: "igb0", Tag: 60, Description: "iot"}) {
		t.Fatal("want match")
	}
	if VLANMatchesWrite(rows[0], VLANWrite{Parent: "igb0", Tag: 61}) {
		t.Fatal("want tag mismatch")
	}
	if !BridgeMembersMatch([]string{"igb0", "igb1"}, []string{"igb1", "igb0"}) {
		t.Fatal("members order-insensitive")
	}
	if BridgeMembersMatch([]string{"igb0"}, []string{"igb0", "igb1"}) {
		t.Fatal("want length mismatch")
	}
	if VLANMatchesWrite(rows[0], VLANWrite{Parent: "igb0", Tag: 60, Description: "other"}) {
		t.Fatal("want description mismatch")
	}
}

func TestGetVLANs_SkipsMalformedAndReconfigureErrors(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "search_item") {
			testutil.WriteBody(w, `{"total":2,"rows":["x",{"uuid":"","tag":"1"},{"uuid":"ok","if":"igb1","tag":"10"}]}`)
			return
		}
		testutil.WriteBody(w, `{"status":"failed"}`)
	}))
	got, err := c.GetVLANs(context.Background())
	if err != nil || len(got) != 1 || got[0].UUID != "ok" {
		t.Fatalf("got %+v %v", got, err)
	}
	if err := c.ReconfigureVLANs(context.Background()); err == nil {
		t.Fatal("expected reconfigure status error")
	}
	failResult, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testutil.WriteBody(w, `{"result":"nope"}`)
	}))
	if err := failResult.ReconfigureBridges(context.Background()); err == nil {
		t.Fatal("expected reconfigure result error")
	}
	badJSON, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testutil.WriteBody(w, `{`)
	}))
	if err := badJSON.ReconfigureVLANs(context.Background()); err == nil {
		t.Fatal("expected decode error")
	}
}
