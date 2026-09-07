package omada

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestGetWLANGroupsAndSSIDs(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "wlan-groups"):
			writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"g1","name":"Default"}]}`)
		case strings.HasSuffix(r.URL.Path, "/ssids"):
			writeEnvelope(w, 0, "", `{"totalRows":1,"data":[{"id":"s1","name":"iot-wifi","ssid":"iot","enable":true,"vlanId":60,"security":"wpa2"}]}`)
		default:
			writeEnvelope(w, -1600, "bad", "null")
		}
	}))
	groups, err := c.GetWLANGroups(context.Background(), "s1")
	if err != nil || len(groups) != 1 || groups[0].Name != "Default" {
		t.Fatalf("groups = %+v, %v", groups, err)
	}
	ssids, err := c.GetSSIDs(context.Background(), "s1")
	if err != nil || len(ssids) != 1 || ssids[0].SSID != "iot" {
		t.Fatalf("ssids = %+v, %v", ssids, err)
	}
}

func TestCreateUpdateDeleteSSID(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			writeEnvelope(w, 0, "", `{"id":"s-new"}`)
		default:
			writeEnvelope(w, 0, "", `{}`)
		}
	}))
	id, err := c.CreateSSID(context.Background(), "s1", SSIDWrite{Name: "iot-wifi", SSID: "iot"})
	if err != nil || id != "s-new" {
		t.Fatalf("create = %q %v", id, err)
	}
	if err := c.UpdateSSID(context.Background(), "s1", "s1", SSIDWrite{Name: "iot-wifi", SSID: "iot"}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if err := c.DeleteSSID(context.Background(), "s1", "s1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
}

func TestWLANErrors(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, -1, "nope", "null")
	}))
	if _, err := c.GetWLANGroups(context.Background(), "s1"); err == nil {
		t.Fatal("expected groups error")
	}
	if _, err := c.GetSSIDs(context.Background(), "s1"); err == nil {
		t.Fatal("expected ssids error")
	}
	if _, err := c.CreateSSID(context.Background(), "s1", SSIDWrite{Name: "x", SSID: "x"}); err == nil {
		t.Fatal("expected create error")
	}
	if err := c.UpdateSSID(context.Background(), "s1", "s1", SSIDWrite{Name: "x"}); err == nil {
		t.Fatal("expected update error")
	}
	if err := c.DeleteSSID(context.Background(), "s1", "s1"); err == nil {
		t.Fatal("expected delete error")
	}
	empty, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			writeEnvelope(w, 0, "", `{}`)
			return
		}
		writeEnvelope(w, 0, "", `{"totalRows":0}`)
	}))
	if _, err := empty.CreateSSID(context.Background(), "s1", SSIDWrite{Name: "x", SSID: "x"}); err == nil {
		t.Fatal("expected missing id")
	}
	groups, err := empty.GetWLANGroups(context.Background(), "s1")
	if err != nil || groups == nil {
		t.Fatalf("empty groups = %+v %v", groups, err)
	}
}

func TestFindSSIDAndMatch(t *testing.T) {
	rows := []SSID{{ID: "s1", Name: "iot-wifi", SSID: "iot", Enabled: true, VLANID: 60, Security: "wpa2"}}
	got, ok := FindSSID(rows, "iot")
	if !ok || got.ID != "s1" {
		t.Fatalf("FindSSID = %+v %v", got, ok)
	}
	w := SSIDWrite{SSID: "iot", Enabled: true, VLANID: 60, Security: "wpa2"}
	if !SSIDMatchesWrite(got, w) {
		t.Fatal("want match")
	}
	w.VLANID = 1
	if SSIDMatchesWrite(got, w) {
		t.Fatal("want mismatch")
	}
}
