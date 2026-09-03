package omada

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// BDD: uplink-info is a POST with a deviceMacs body; the result is a direct
// (unpaged) array, one row per queried MAC.
func TestGetUplinkInfo_DirectArray(t *testing.T) {
	var gotMethod, gotPath, gotBody string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotBody = readBody(t, r)
		writeEnvelope(w, 0, "", `[{"mac":"aa:bb:cc:dd:ee:00","uplinkDeviceMac":"11:22:33:44:55:66",
			"uplinkDeviceName":"Big","uplinkDevicePort":"8","linkSpeed":3,"duplex":2}]`)
	}))

	rows, err := c.GetUplinkInfo(context.Background(), "s1", []string{"aa:bb:cc:dd:ee:00"})
	if err != nil {
		t.Fatalf("GetUplinkInfo: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q, want POST", gotMethod)
	}
	if gotPath != "/openapi/v1/abc123/sites/s1/devices/uplink-info" {
		t.Errorf("path = %q, want uplink-info path", gotPath)
	}
	if len(rows) != 1 || rows[0].UplinkDevicePort != "8" || rows[0].LinkSpeed != 3 {
		t.Errorf("rows = %+v, want port 8 / 1000M", rows)
	}
	var body map[string][]string
	if err := json.Unmarshal([]byte(gotBody), &body); err != nil {
		t.Fatalf("body %q not valid JSON: %v", gotBody, err)
	}
	if len(body["deviceMacs"]) != 1 || body["deviceMacs"][0] != "aa:bb:cc:dd:ee:00" {
		t.Errorf("body deviceMacs = %v, want the queried MAC", body["deviceMacs"])
	}
}

// BDD: uplink-info with no matching rows returns an empty result, not an error.
func TestGetUplinkInfo_EmptyResult(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, 0, "", "[]")
	}))
	rows, err := c.GetUplinkInfo(context.Background(), "s1", []string{"aa:bb:cc:dd:ee:99"})
	if err != nil {
		t.Fatalf("GetUplinkInfo: %v", err)
	}
	if len(rows) != 0 {
		t.Errorf("rows = %+v, want empty", rows)
	}
}

// BDD: uplink-info controller error surfaces wrapped.
func TestGetUplinkInfo_ControllerError(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, -33004, "site busy", "null")
	}))
	_, err := c.GetUplinkInfo(context.Background(), "s1", []string{"aa:bb:cc:dd:ee:00"})
	if err == nil || !strings.Contains(err.Error(), "fetching uplink info") {
		t.Fatalf("error = %v, want wrapped uplink-info error", err)
	}
}

// BDD: ports overview is a paged GET; a single-page response returns the rows.
func TestGetSwitchPortsOverview(t *testing.T) {
	var gotMethod, gotPath, gotQuery string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		writeEnvelope(w, 0, "", `{"totalRows":1,"currentPage":1,"currentSize":1,
			"data":[{"port":8,"portName":"P8","switchMac":"11:22:33:44:55:66","switchName":"Big",
			"networkMode":0,"profileId":"prof-1","profileName":"Trunk"}]}`)
	}))

	rows, err := c.GetSwitchPortsOverview(context.Background(), "s1")
	if err != nil {
		t.Fatalf("GetSwitchPortsOverview: %v", err)
	}
	if gotMethod != http.MethodGet {
		t.Errorf("method = %q, want GET", gotMethod)
	}
	if gotPath != "/openapi/v1/abc123/sites/s1/switches/ports/overview" {
		t.Errorf("path = %q, want ports overview path", gotPath)
	}
	if !strings.Contains(gotQuery, "page=1") || !strings.Contains(gotQuery, "pageSize=200") {
		t.Errorf("query = %q, want paging params", gotQuery)
	}
	if len(rows) != 1 || rows[0].Port != 8 || rows[0].ProfileID != "prof-1" {
		t.Errorf("rows = %+v, want port 8 with profile", rows)
	}
}

// BDD: ports overview tolerates the direct-array (non-paged) payload.
func TestGetSwitchPortsOverview_DirectArray(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, 0, "", `[{"port":1,"switchMac":"11:22:33:44:55:66"}]`)
	}))
	rows, err := c.GetSwitchPortsOverview(context.Background(), "s1")
	if err != nil {
		t.Fatalf("GetSwitchPortsOverview: %v", err)
	}
	if len(rows) != 1 {
		t.Errorf("rows = %+v, want one row", rows)
	}
}

// BDD: ports overview empty site returns an empty (non-nil) slice.
func TestGetSwitchPortsOverview_Empty(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, 0, "", `{"totalRows":0,"currentPage":1,"currentSize":0,"data":[]}`)
	}))
	rows, err := c.GetSwitchPortsOverview(context.Background(), "s1")
	if err != nil {
		t.Fatalf("GetSwitchPortsOverview: %v", err)
	}
	if rows == nil || len(rows) != 0 {
		t.Errorf("rows = %#v, want empty non-nil slice", rows)
	}
}

// BDD: ports overview controller error surfaces wrapped.
func TestGetSwitchPortsOverview_ControllerError(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, -1005, "no permission", "null")
	}))
	_, err := c.GetSwitchPortsOverview(context.Background(), "s1")
	if err == nil || !strings.Contains(err.Error(), "fetching switch ports overview") {
		t.Fatalf("error = %v, want wrapped overview error", err)
	}
}

// BDD: LAN profiles is a paged GET.
func TestGetLanProfiles(t *testing.T) {
	var gotMethod, gotPath string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		writeEnvelope(w, 0, "", `{"totalRows":1,"currentPage":1,"currentSize":1,
			"data":[{"id":"prof-1","name":"Trunk","poe":2,"nativeNetworkId":"n1",
			"tagNetworkIds":["n30","n50"],"untagNetworkIds":["n1"],"dot1x":2,"bandWidthCtrlType":0}]}`)
	}))

	profiles, err := c.GetLanProfiles(context.Background(), "s1")
	if err != nil {
		t.Fatalf("GetLanProfiles: %v", err)
	}
	if gotMethod != http.MethodGet || gotPath != "/openapi/v1/abc123/sites/s1/lan-profiles" {
		t.Errorf("method/path = %q %q, want GET lan-profiles", gotMethod, gotPath)
	}
	if len(profiles) != 1 || profiles[0].ID != "prof-1" || len(profiles[0].TagNetworkIDs) != 2 {
		t.Errorf("profiles = %+v, want the trunk profile", profiles)
	}
}

// BDD: LAN profiles empty site returns an empty (non-nil) slice.
func TestGetLanProfiles_Empty(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, 0, "", `{"totalRows":0,"currentPage":1,"currentSize":0,"data":[]}`)
	}))
	profiles, err := c.GetLanProfiles(context.Background(), "s1")
	if err != nil {
		t.Fatalf("GetLanProfiles: %v", err)
	}
	if profiles == nil || len(profiles) != 0 {
		t.Errorf("profiles = %#v, want empty non-nil slice", profiles)
	}
}

// BDD: LAN profiles controller error surfaces wrapped.
func TestGetLanProfiles_ControllerError(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, -1005, "no permission", "null")
	}))
	_, err := c.GetLanProfiles(context.Background(), "s1")
	if err == nil || !strings.Contains(err.Error(), "fetching LAN profiles") {
		t.Fatalf("error = %v, want wrapped profiles error", err)
	}
}

// BDD: create POSTs the required-field body and returns the new profile id.
func TestCreateLanProfile(t *testing.T) {
	var gotMethod, gotPath, gotBody string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotBody = readBody(t, r)
		writeEnvelope(w, 0, "", `{"id":"prof-new"}`)
	}))

	id, err := c.CreateLanProfile(context.Background(), "s1", LanProfile{
		Name: "Trunk", PoE: PoEDoNotModify, NativeNetworkID: "n1",
		TagNetworkIDs: []string{"n30", "n50"}, UntagNetworkIDs: []string{"n1"},
		Dot1x: Dot1xAuto, BandWidthCtrlType: BandWidthCtrlOff,
	})
	if err != nil {
		t.Fatalf("CreateLanProfile: %v", err)
	}
	if id != "prof-new" {
		t.Errorf("id = %q, want prof-new", id)
	}
	if gotMethod != http.MethodPost || gotPath != "/openapi/v1/abc123/sites/s1/lan-profiles" {
		t.Errorf("method/path = %q %q, want POST lan-profiles", gotMethod, gotPath)
	}
	var body LanProfile
	if err := json.Unmarshal([]byte(gotBody), &body); err != nil {
		t.Fatalf("body %q not valid JSON: %v", gotBody, err)
	}
	if body.Name != "Trunk" || body.NativeNetworkID != "n1" || body.Dot1x != Dot1xAuto {
		t.Errorf("body = %+v, want required fields set", body)
	}
	if len(body.TagNetworkIDs) != 2 || body.TagNetworkIDs[0] != "n30" || body.TagNetworkIDs[1] != "n50" {
		t.Errorf("body tag = %v, want [n30 n50]", body.TagNetworkIDs)
	}
	if len(body.UntagNetworkIDs) != 1 || body.UntagNetworkIDs[0] != "n1" {
		t.Errorf("body untag = %v, want [n1]", body.UntagNetworkIDs)
	}
	// The controller's required booleans must be present even when false.
	if !strings.Contains(gotBody, `"portIsolationEnable":false`) ||
		!strings.Contains(gotBody, `"lldpMedEnable":false`) ||
		!strings.Contains(gotBody, `"spanningTreeEnable":false`) ||
		!strings.Contains(gotBody, `"loopbackDetectEnable":false`) {
		t.Errorf("body = %q, want required booleans explicitly encoded", gotBody)
	}
}

// BDD: create surfaces a missing id as an error.
func TestCreateLanProfile_NoID(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, 0, "", `{}`)
	}))
	_, err := c.CreateLanProfile(context.Background(), "s1", LanProfile{Name: "x", PoE: 2, NativeNetworkID: "n1", Dot1x: 2})
	if err == nil || !strings.Contains(err.Error(), "no profile id") {
		t.Fatalf("error = %v, want missing-id error", err)
	}
}

// BDD: create controller error surfaces wrapped.
func TestCreateLanProfile_ControllerError(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, -1001, "invalid params", "null")
	}))
	_, err := c.CreateLanProfile(context.Background(), "s1", LanProfile{Name: "x", PoE: 2, NativeNetworkID: "n1", Dot1x: 2})
	if err == nil || !strings.Contains(err.Error(), "creating LAN profile") {
		t.Fatalf("error = %v, want wrapped create error", err)
	}
}

// BDD: set-port-profile PUTs a bare profileId body to the port profile path.
func TestSetPortProfile(t *testing.T) {
	var gotMethod, gotPath, gotBody string
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotBody = readBody(t, r)
		writeEnvelope(w, 0, "", "null")
	}))

	if err := c.SetPortProfile(context.Background(), "s1", "11:22:33:44:55:66", 8, "prof-new"); err != nil {
		t.Fatalf("SetPortProfile: %v", err)
	}
	if gotMethod != http.MethodPut {
		t.Errorf("method = %q, want PUT", gotMethod)
	}
	if gotPath != "/openapi/v1/abc123/sites/s1/switches/11:22:33:44:55:66/ports/8/profile" {
		t.Errorf("path = %q, want port profile path", gotPath)
	}
	if gotBody != `{"profileId":"prof-new"}` {
		t.Errorf("body = %q, want bare profileId", gotBody)
	}
}

// BDD: set-port-profile controller error surfaces wrapped and names the port.
func TestSetPortProfile_ControllerError(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeEnvelope(w, -39701, "port does not exist", "null")
	}))
	err := c.SetPortProfile(context.Background(), "s1", "11:22:33:44:55:66", 99, "prof-x")
	if err == nil || !strings.Contains(err.Error(), "setting LAN profile on port 99") {
		t.Fatalf("error = %v, want wrapped per-port error", err)
	}
}

// BDD: FindLanProfile matches on the (native, tagged, untagged) ID sets,
// order-insensitive, and returns nil when nothing matches.
func TestFindLanProfile(t *testing.T) {
	profiles := []LanProfile{
		{ID: "a", Name: "access", NativeNetworkID: "n1", TagNetworkIDs: nil, UntagNetworkIDs: []string{"n1"}},
		{ID: "b", Name: "trunk", NativeNetworkID: "n1", TagNetworkIDs: []string{"n50", "n30"}, UntagNetworkIDs: []string{"n1"}},
	}

	got := FindLanProfile(profiles, "n1", []string{"n30", "n50"}, []string{"n1"})
	if got == nil || got.ID != "b" {
		t.Errorf("FindLanProfile = %v, want profile b (trunk)", got)
	}
	// Order-insensitive on the tagged set.
	got = FindLanProfile(profiles, "n1", []string{"n50", "n30"}, []string{"n1"})
	if got == nil || got.ID != "b" {
		t.Errorf("FindLanProfile (reordered tags) = %v, want profile b", got)
	}
	// Different native -> no match.
	if FindLanProfile(profiles, "n9", []string{"n30", "n50"}, []string{"n1"}) != nil {
		t.Error("FindLanProfile matched on wrong native, want nil")
	}
	// Different untag set -> no match.
	if FindLanProfile(profiles, "n1", []string{"n30", "n50"}, []string{"n30"}) != nil {
		t.Error("FindLanProfile matched on wrong untag set, want nil")
	}
	// No tagged at all -> no match against the trunk.
	if FindLanProfile(profiles, "n1", nil, []string{"n1"}) == nil {
		// This SHOULD match the access profile (a), so a nil here is wrong.
		t.Error("FindLanProfile (nil tags) = nil, want the access profile")
	}
}

// BDD: sortedIDEqual is order-insensitive and size-sensitive.
func TestSortedIDEqual(t *testing.T) {
	if !sortedIDEqual([]string{"a", "b"}, []string{"b", "a"}) {
		t.Error("sortedIDEqual: reordered equal sets should match")
	}
	if sortedIDEqual([]string{"a"}, []string{"a", "b"}) {
		t.Error("sortedIDEqual: different sizes should not match")
	}
	if !sortedIDEqual(nil, nil) {
		t.Error("sortedIDEqual: nil,nil should be equal")
	}
	// nil vs empty: both length 0, treated equal (controller sends [] or omits).
	if !sortedIDEqual(nil, []string{}) {
		t.Error("sortedIDEqual: nil and empty should be equal")
	}
}
