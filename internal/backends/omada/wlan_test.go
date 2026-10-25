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
	// The service conversion always derives Name (from the request's name
	// or ssid), so a real write payload always carries it.
	w := SSIDWrite{Name: "iot-wifi", SSID: "iot", Enabled: true, VLANID: 60, Security: "wpa2"}
	if !SSIDMatchesWrite(got, w) {
		t.Fatal("want match")
	}
	w.VLANID = 1
	if SSIDMatchesWrite(got, w) {
		t.Fatal("want mismatch")
	}
}

// TestSSIDMatchesWrite_BandAndCaseChangesCount reproduces #181: band-only
// and broadcast-SSID case-only changes must produce an update, not a
// false no-op. Broadcast SSIDs are case-sensitive on the air.
func TestSSIDMatchesWrite_BandAndCaseChangesCount(t *testing.T) {
	s := SSID{Name: "iot-wifi", SSID: "iot", Enabled: true, VLANID: 60, Security: "wpa2", Band: "2.4GHz"}
	base := SSIDWrite{Name: "iot-wifi", SSID: "iot", Enabled: true, VLANID: 60, Security: "wpa2", Band: "2.4GHz"}

	if !SSIDMatchesWrite(s, base) {
		t.Fatal("identical write must match")
	}

	bandChanged := base
	bandChanged.Band = "5GHz"
	if SSIDMatchesWrite(s, bandChanged) {
		t.Error("band-only change must not be a no-op")
	}

	caseChanged := base
	caseChanged.SSID = "IOT"
	if SSIDMatchesWrite(s, caseChanged) {
		t.Error("broadcast-SSID case change must not be a no-op (SSIDs are case-sensitive)")
	}

	nameChanged := base
	nameChanged.Name = "iot-admin-renamed"
	if SSIDMatchesWrite(s, nameChanged) {
		t.Error("administrative-name change must not be a no-op")
	}
}
