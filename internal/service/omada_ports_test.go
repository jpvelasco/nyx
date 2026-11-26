package service

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
)

// --- port-profile (uplink / switch ports / lan profiles / plan / apply) ---

// omadaPortState is the mutable controller state for port-profile tests:
// the site's LAN profiles plus each port's bound profileId. The Fail*
// flags inject controller errors for specific write/read phases so the
// service's error returns are exercised without a live controller.
type omadaPortState struct {
	Profiles          []omadabackend.LanProfile
	PortProfiles      map[int]string
	NextID            int
	FailBind          bool // fail the per-port profile PUT (bind)
	FailCreateProfile bool // fail the LAN-profile create POST
	OverviewFailAfter int  // fail ports-overview GETs once seen >= this many times (0 = off)
	overviewSeen      int
	Port8Override     bool // report port 8 with profileOverrideEnable
	ProfilesFailAfter int  // fail lan-profiles GETs once seen >= this many times (0 = off)
	profilesSeen      int
	NetworksFailAfter int // fail lan-networks GETs once seen >= this many times (0 = off)
	networksSeen      int
}

// omadaPortOpts is the standard (synthetic) OmadaOptions for port-profile
// tests.
func omadaPortOpts(host string) OmadaOptions {
	return OmadaOptions{Host: host, ClientID: "a", ClientSecret: "b", SkipTLSVerify: true}
}

// omadaPortNets is the fixture site's declared LAN networks.
const omadaPortNets = `[
	{"id":"n1","name":"trusted","purpose":"lan","vlan":1,"gatewaySubnet":"10.0.10.1/24","deviceMac":"aa:bb:cc:dd:ee:00"},
	{"id":"n2","name":"gaming","purpose":"lan","vlan":30,"gatewaySubnet":"10.0.10.1/24","deviceMac":"aa:bb:cc:dd:ee:00"},
	{"id":"n3","name":"media","purpose":"lan","vlan":50,"gatewaySubnet":"10.0.10.1/24","deviceMac":"aa:bb:cc:dd:ee:00"},
	{"id":"n4","name":"Personal","purpose":"lan","vlan":60,"gatewaySubnet":"10.0.10.1/24","deviceMac":"aa:bb:cc:dd:ee:00"}]`

// omadaPortBaseHandler serves the port-profile endpoints against st; the
// uplink-info, ports-overview, lan-profiles (GET/POST), and per-port
// profile-PUT paths are stateful so plan/apply tests observe real before/
// after changes.
func omadaPortBaseHandler(t *testing.T, st *omadaPortState) http.HandlerFunc {
	t.Helper()
	const swBase = "/openapi/v1/abc123/sites/s1/switches/"
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if r.Method == http.MethodPut && strings.HasPrefix(path, swBase) {
			handleProfilePut(t, w, r, st, swBase)
			return
		}
		switch {
		case path == "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case path == "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case path == "/openapi/v1/abc123/sites/s1/lan-networks":
			st.networksSeen++
			if st.NetworksFailAfter > 0 && st.networksSeen >= st.NetworksFailAfter {
				writeOmadaEnvelope(w, -33004, `{"detail":"site busy"}`)
				return
			}
			writeOmadaEnvelope(w, 0, `{"totalRows":4,"data":`+omadaPortNets+`}`)
		case path == "/openapi/v1/abc123/sites/s1/devices/uplink-info" && r.Method == http.MethodPost:
			var body struct {
				MACs []string `json:"deviceMacs"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Errorf("uplink-info body decode: %v", err)
			}
			// The client forwards MACs as given; compare normalized so the
			// assertion holds for any casing/separators.
			if omadabackend.NormalizeMAC(body.MACs[0]) != omadabackend.NormalizeMAC("aa:bb:cc:dd:ee:01") {
				t.Errorf("uplink-info deviceMacs = %v, want the queried MAC passed through", body.MACs)
			}
			writeOmadaEnvelope(w, 0, `[{"mac":"aa:bb:cc:dd:ee:01","uplinkDeviceMac":"bb:11:22:33:44:55","uplinkDeviceName":"SW-CORE","uplinkDevicePort":"8","linkSpeed":3,"duplex":2}]`)
		case path == "/openapi/v1/abc123/sites/s1/switches/ports/overview":
			st.overviewSeen++
			if st.OverviewFailAfter > 0 && st.overviewSeen >= st.OverviewFailAfter {
				writeOmadaEnvelope(w, -33004, `{"detail":"site busy"}`)
				return
			}
			writePortOverview(w, st)
		case path == "/openapi/v1/abc123/sites/s1/lan-profiles":
			switch r.Method {
			case http.MethodGet:
				st.profilesSeen++
				if st.ProfilesFailAfter > 0 && st.profilesSeen >= st.ProfilesFailAfter {
					writeOmadaEnvelope(w, -33004, `{"detail":"site busy"}`)
					return
				}
				writeOmadaEnvelope(w, 0, `{"totalRows":`+strconv.Itoa(len(st.Profiles))+`,"data":`+string(mustMarshalJSON(st.Profiles))+`}`)
			case http.MethodPost:
				if st.FailCreateProfile {
					writeOmadaEnvelope(w, -1001, `{"detail":"invalid params"}`)
					return
				}
				var p omadabackend.LanProfile
				if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
					t.Errorf("lan-profiles create decode: %v", err)
				}
				st.NextID++
				id := fmt.Sprintf("P%d", 100+st.NextID)
				p.ID = id
				st.Profiles = append(st.Profiles, p)
				writeOmadaEnvelope(w, 0, `{"id":"`+id+`"}`)
			}
		default:
			t.Errorf("unexpected %s %s", r.Method, path)
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

// writePortOverview serves the fixture ports-overview page: ports 1, 9, and
// 10 on the second switch, port 8 on the core switch. Each row's bound
// profile tracks the mutable state so an apply is visible on re-read.
func writePortOverview(w io.Writer, st *omadaPortState) {
	rows := []map[string]any{
		{"port": 1, "portName": "GE1", "switchMac": "aa:bb:cc:dd:ee:01", "switchName": "SW-A", "connectedStatus": 0, "disable": false, "networkMode": 1, "nativeNetworkId": "n1", "nativeBridgeVlan": 0, "networkTagsSetting": 0, "profileId": st.PortProfiles[1], "profileName": "Access-trusted", "profileOverrideEnable": false},
		{"port": 8, "portName": "GE8", "switchMac": "bb:11:22:33:44:55", "switchName": "SW-CORE", "connectedStatus": 0, "disable": false, "networkMode": 0, "nativeNetworkId": "n1", "nativeBridgeVlan": 0, "networkTagsSetting": 0, "profileId": st.PortProfiles[8], "profileName": "Access-trusted", "profileOverrideEnable": st.Port8Override},
		{"port": 9, "portName": "GE9", "switchMac": "aa:bb:cc:dd:ee:01", "switchName": "SW-A", "connectedStatus": 1, "disable": false, "networkMode": 0, "nativeNetworkId": "", "nativeBridgeVlan": 0, "networkTagsSetting": 0, "profileId": st.PortProfiles[9], "profileName": "media+gaming", "profileOverrideEnable": false},
		{"port": 10, "portName": "GE10", "switchMac": "aa:bb:cc:dd:ee:01", "switchName": "SW-A", "connectedStatus": 0, "disable": false, "networkMode": 1, "nativeNetworkId": "n1", "nativeBridgeVlan": 0, "networkTagsSetting": 0, "profileId": st.PortProfiles[10], "profileName": "Access-trusted", "profileOverrideEnable": false},
	}
	writeOmadaEnvelope(w, 0, `{"totalRows":`+strconv.Itoa(len(rows))+`,"data":`+string(mustMarshalJSON(rows))+`}`)
}

// handleProfilePut applies a per-port profileId PUT against the state. The
// path is {swBase}{mac}/ports/{port}/profile; the MAC is split-safe
// (controller MACs use colons or dashes, never slashes).
func handleProfilePut(t *testing.T, w http.ResponseWriter, r *http.Request, st *omadaPortState, swBase string) {
	t.Helper()
	var body struct {
		ProfileID string `json:"profileId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		t.Errorf("profile PUT decode: %v", err)
	}
	if st.FailBind {
		writeOmadaEnvelope(w, -32000, `null`)
		return
	}
	parts := strings.Split(strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, swBase), "/"), "/")
	if len(parts) != 4 || parts[1] != "ports" || parts[3] != "profile" {
		t.Errorf("profile PUT path %q: unrecognized shape", r.URL.Path)
		return
	}
	port, err := strconv.Atoi(parts[2])
	if err != nil {
		t.Errorf("profile PUT path %q: port %q: %v", r.URL.Path, parts[2], err)
		return
	}
	st.PortProfiles[port] = body.ProfileID
	writeOmadaEnvelope(w, 0, `null`)
}

// omadaPortStateFresh returns the standard fixture state: ports 1, 8, and
// 10 bound to the trusted access profile, port 9 (second switch) bound to
// the media/gaming trunk profile.
func omadaPortStateFresh() *omadaPortState {
	return &omadaPortState{
		Profiles: []omadabackend.LanProfile{
			{ID: "P1", Name: "Access-trusted", PoE: 2, NativeNetworkID: "n1", TagNetworkIDs: []string{}, UntagNetworkIDs: []string{"n1"}, Dot1x: 2, BandWidthCtrlType: 0},
			{ID: "P2", Name: "media", PoE: 2, NativeNetworkID: "n3", TagNetworkIDs: []string{}, UntagNetworkIDs: []string{"n3"}, Dot1x: 2, BandWidthCtrlType: 0},
			{ID: "P3", Name: "media+gaming", PoE: 2, NativeNetworkID: "n3", TagNetworkIDs: []string{"n1", "n2"}, UntagNetworkIDs: []string{"n3"}, Dot1x: 2, BandWidthCtrlType: 0},
		},
		PortProfiles: map[int]string{1: "P1", 8: "P1", 9: "P3", 10: "P1"},
	}
}

func mustMarshalJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func TestOmadaServiceGetUplinkInfo(t *testing.T) {
	st := omadaPortStateFresh()
	ts := omadaTestServer(t, omadaPortBaseHandler(t, st))
	rows, err := NewOmadaService().GetUplinkInfo(context.Background(), omadaPortOpts(ts.URL), []string{"aa:bb:cc:dd:ee:01"})
	if err != nil {
		t.Fatalf("GetUplinkInfo: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %+v, want 1", rows)
	}
	r := rows[0]
	if r.MAC != "aa:bb:cc:dd:ee:01" || r.UplinkDevicePort != "8" || r.UplinkDeviceName != "SW-CORE" || r.LinkSpeed != 3 || r.Duplex != 2 {
		t.Errorf("row = %+v", r)
	}
	if r.LinkSpeedSource != omadabackend.LinkSpeedConfigured {
		t.Errorf("link_speed_source = %q, want %q (configured, not negotiated)", r.LinkSpeedSource, omadabackend.LinkSpeedConfigured)
	}
}

func TestOmadaServiceGetUplinkInfo_FetchFails(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		default:
			writeOmadaEnvelope(w, -33004, `null`)
		}
	})
	_, err := NewOmadaService().GetUplinkInfo(context.Background(), omadaPortOpts(ts.URL), []string{"aa:bb:cc:dd:ee:01"})
	if err == nil {
		t.Fatal("expected uplink-info fetch failure to propagate")
	}
}

func TestOmadaServiceListSwitchPorts(t *testing.T) {
	st := omadaPortStateFresh()
	ts := omadaTestServer(t, omadaPortBaseHandler(t, st))
	all, err := NewOmadaService().ListSwitchPorts(context.Background(), omadaPortOpts(ts.URL), "")
	if err != nil {
		t.Fatalf("ListSwitchPorts: %v", err)
	}
	if len(all) != 4 {
		t.Fatalf("all = %d rows, want 4", len(all))
	}

	filtered, err := NewOmadaService().ListSwitchPorts(context.Background(), omadaPortOpts(ts.URL), "bb:11:22:33:44:55")
	if err != nil {
		t.Fatalf("ListSwitchPorts filtered: %v", err)
	}
	if len(filtered) != 1 {
		t.Fatalf("filtered = %d rows, want 1", len(filtered))
	}
	p := filtered[0]
	if p.Port != 8 || p.NetworkMode != 0 || p.NativeNetwork != "trusted" {
		t.Errorf("port = %+v", p)
	}
	if p.LinkSpeedSource != omadabackend.LinkSpeedConfigured {
		t.Errorf("link_speed_source = %q, want %q", p.LinkSpeedSource, omadabackend.LinkSpeedConfigured)
	}
	if len(p.Tagged) != 0 {
		t.Errorf("port 8 tagged = %v, want empty (profile P1)", p.Tagged)
	}

	// Port 9's row has no native on the wire: it falls back to the
	// referenced profile's native network.
	for _, p := range all {
		if p.Port == 9 && p.SwitchMAC == "aa:bb:cc:dd:ee:01" {
			if p.NativeNetwork != "media" || len(p.Tagged) != 2 || p.Tagged[0] != "trusted" || p.Tagged[1] != "gaming" {
				t.Errorf("port 9 = native %q tagged %v, want media/[trusted gaming]", p.NativeNetwork, p.Tagged)
			}
		}
	}
}

func TestOmadaServiceListSwitchPorts_FetchFails(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/openapi/v1/abc123/sites/s1/lan-networks":
			writeOmadaEnvelope(w, 0, `{"totalRows":4,"data":`+omadaPortNets+`}`)
		default:
			writeOmadaEnvelope(w, -33004, `null`)
		}
	})
	_, err := NewOmadaService().ListSwitchPorts(context.Background(), omadaPortOpts(ts.URL), "")
	if err == nil {
		t.Fatal("expected ports-overview fetch failure to propagate")
	}
}

// TestOmadaServiceListSwitchPorts_SecondAndThirdFetchFail: a partial
// collection set must not be tolerated — a failure on the lan-profiles or
// the networks read is as fatal as one on the ports overview.
func TestOmadaServiceListSwitchPorts_SecondAndThirdFetchFail(t *testing.T) {
	for _, failPath := range []string{
		"/openapi/v1/abc123/sites/s1/lan-profiles",
		"/openapi/v1/abc123/sites/s1/lan-networks",
	} {
		t.Run(failPath[strings.LastIndex(failPath, "/")+1:], func(t *testing.T) {
			ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/openapi/authorize/token":
					writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
				case "/openapi/v1/abc123/sites":
					writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
				case failPath:
					writeOmadaEnvelope(w, -33004, `{"detail":"site busy"}`)
				case "/openapi/v1/abc123/sites/s1/switches/ports/overview":
					writePortOverview(w, omadaPortStateFresh())
				case "/openapi/v1/abc123/sites/s1/lan-profiles":
					writeOmadaEnvelope(w, 0, `{"totalRows":3,"data":[
						{"id":"P1","name":"Access-trusted","nativeNetworkId":"n1","tagNetworkIds":[],"untagNetworkIds":["n1"]},
						{"id":"P2","name":"media","nativeNetworkId":"n3","tagNetworkIds":[],"untagNetworkIds":["n3"]},
						{"id":"P3","name":"media+gaming","nativeNetworkId":"n3","tagNetworkIds":["n1","n2"],"untagNetworkIds":["n3"]}]}`)
				case "/openapi/v1/abc123/sites/s1/lan-networks":
					writeOmadaEnvelope(w, 0, `{"totalRows":4,"data":`+omadaPortNets+`}`)
				default:
					t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			})
			_, err := NewOmadaService().ListSwitchPorts(context.Background(), omadaPortOpts(ts.URL), "")
			if err == nil {
				t.Fatal("expected fetch failure to propagate")
			}
		})
	}
}

func TestOmadaServiceListLanProfiles(t *testing.T) {
	st := omadaPortStateFresh()
	ts := omadaTestServer(t, omadaPortBaseHandler(t, st))
	profiles, err := NewOmadaService().ListLanProfiles(context.Background(), omadaPortOpts(ts.URL))
	if err != nil {
		t.Fatalf("ListLanProfiles: %v", err)
	}
	if len(profiles) != 3 {
		t.Fatalf("profiles = %d, want 3", len(profiles))
	}
	byID := map[string]OmadaLanProfile{}
	for _, p := range profiles {
		byID[p.ID] = p
	}
	p3 := byID["P3"]
	if p3.Name != "media+gaming" || p3.NativeNetwork != "media" || len(p3.TaggedNetworks) != 2 {
		t.Errorf("P3 = %+v", p3)
	}
	if p1 := byID["P1"]; p1.NativeNetwork != "trusted" || len(p1.TaggedNetworks) != 0 {
		t.Errorf("P1 = %+v", p1)
	}
}

func TestOmadaServiceListLanProfiles_FetchFails(t *testing.T) {
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		default:
			writeOmadaEnvelope(w, -33004, `null`)
		}
	})
	_, err := NewOmadaService().ListLanProfiles(context.Background(), omadaPortOpts(ts.URL))
	if err == nil {
		t.Fatal("expected lan-profiles fetch failure to propagate")
	}
}

func TestOmadaServicePlanPort(t *testing.T) {
	st := omadaPortStateFresh()
	ts := omadaTestServer(t, omadaPortBaseHandler(t, st))
	svc := NewOmadaService()
	ctx := context.Background()
	coreMAC := "bb:11:22:33:44:55"

	unchanged, err := svc.PlanPort(ctx, omadaPortOpts(ts.URL), OmadaPortProfileRequest{SwitchMAC: coreMAC, Port: 8, Native: "trusted"})
	if err != nil {
		t.Fatalf("PlanPort unchanged: %v", err)
	}
	if unchanged.Outcome != "unchanged" || unchanged.ProfileID != "P1" || unchanged.Site != "HQ" {
		t.Errorf("unchanged = outcome %q profile %q site %q", unchanged.Outcome, unchanged.ProfileID, unchanged.Site)
	}
	if unchanged.Current == nil || unchanged.Current.ProfileID != "P1" || unchanged.CurrentProfile == nil || unchanged.CurrentProfile.Name != "Access-trusted" {
		t.Errorf("unchanged current = %+v / %+v", unchanged.Current, unchanged.CurrentProfile)
	}

	rebind, err := svc.PlanPort(ctx, omadaPortOpts(ts.URL), OmadaPortProfileRequest{
		SwitchMAC: "AA:BB:CC:DD:EE:01", Port: 10, Native: "media", Tagged: []string{"trusted", "gaming"},
	})
	if err != nil {
		t.Fatalf("PlanPort rebind: %v", err)
	}
	if rebind.Outcome != "rebind" || rebind.ProfileID != "P3" || rebind.ProfileName != "media+gaming" {
		t.Errorf("rebind = outcome %q profile %q name %q", rebind.Outcome, rebind.ProfileID, rebind.ProfileName)
	}
	if rebind.CurrentProfile == nil || rebind.CurrentProfile.ID != "P1" {
		t.Errorf("rebind current profile = %+v", rebind.CurrentProfile)
	}

	create, err := svc.PlanPort(ctx, omadaPortOpts(ts.URL), OmadaPortProfileRequest{
		SwitchMAC: "AA:BB:CC:DD:EE:01", Port: 1, Native: "Personal", Tagged: []string{"media"},
	})
	if err != nil {
		t.Fatalf("PlanPort create: %v", err)
	}
	if create.Outcome != "create" || create.ProfileCreate != true || create.ProfileName != "Personal+trunk(1)" {
		t.Errorf("create = outcome %q create %v name %q", create.Outcome, create.ProfileCreate, create.ProfileName)
	}
}

func TestOmadaServicePlanPort_Errors(t *testing.T) {
	st := omadaPortStateFresh()
	ts := omadaTestServer(t, omadaPortBaseHandler(t, st))
	svc := NewOmadaService()
	ctx := context.Background()
	opts := omadaPortOpts(ts.URL)
	coreMAC := "bb:11:22:33:44:55"

	_, err := svc.PlanPort(ctx, opts, OmadaPortProfileRequest{SwitchMAC: coreMAC, Port: 9, Native: "trusted"})
	if err == nil || !strings.Contains(err.Error(), "port 9 not found on switch") {
		t.Errorf("missing port: err = %v", err)
	}

	_, err = svc.PlanPort(ctx, opts, OmadaPortProfileRequest{SwitchMAC: coreMAC, Port: 8, Native: "Nope"})
	if err == nil || !strings.Contains(err.Error(), `network "Nope" is not a declared LAN network`) {
		t.Errorf("unknown network: err = %v", err)
	}

	_, err = svc.PlanPort(ctx, opts, OmadaPortProfileRequest{
		SwitchMAC: coreMAC, Port: 8, Native: "media", Tagged: []string{"media"},
	})
	if err == nil || !strings.Contains(err.Error(), "must not also appear in the tagged list") {
		t.Errorf("overlap: err = %v", err)
	}
}

func TestOmadaServiceApplyPortProfile_Outcomes(t *testing.T) {
	st := omadaPortStateFresh()
	ts := omadaTestServer(t, omadaPortBaseHandler(t, st))
	svc := NewOmadaService()
	ctx := context.Background()
	opts := omadaPortOpts(ts.URL)
	coreMAC := "bb:11:22:33:44:55"

	// Idempotent: the bound profile already matches → unchanged, no writes.
	beforeProfiles := len(st.Profiles)
	res, err := svc.ApplyPortProfile(ctx, opts, OmadaPortProfileRequest{SwitchMAC: coreMAC, Port: 8, Native: "trusted"}, false)
	if err != nil {
		t.Fatalf("apply unchanged: %v", err)
	}
	if res.Outcome != "unchanged" || res.DryRun || len(st.PortProfiles) != 4 || len(st.Profiles) != beforeProfiles {
		t.Errorf("unchanged = %+v, mutations: portProfile=%v profiles=%d", res, st.PortProfiles, len(st.Profiles))
	}
	if res.Before == "" || res.After == "" || res.Before != res.After {
		t.Errorf("unchanged evidence = before %q after %q", res.Before, res.After)
	}

	// Rebind: port 10 is bound to the access profile; the matching member
	// profile P3 exists → bound without a create.
	res, err = svc.ApplyPortProfile(ctx, opts, OmadaPortProfileRequest{
		SwitchMAC: "AA:BB:CC:DD:EE:01", Port: 10, Native: "media", Tagged: []string{"trusted", "gaming"},
	}, false)
	if err != nil {
		t.Fatalf("apply rebind: %v", err)
	}
	if res.Outcome != "bound" || res.ProfileID != "P3" || res.ProfileCreate {
		t.Errorf("rebind = %+v", res)
	}
	if st.PortProfiles[10] != "P3" {
		t.Errorf("port 10 profile = %q, want P3", st.PortProfiles[10])
	}
	if !strings.Contains(res.After, `"P3"`) || !strings.Contains(res.Before, `"P1"`) {
		t.Errorf("evidence before=%s after=%s", res.Before, res.After)
	}

	// Create: no member-matching profile → create with the derived name and
	// safe defaults, then bind.
	res, err = svc.ApplyPortProfile(ctx, opts, OmadaPortProfileRequest{
		SwitchMAC: coreMAC, Port: 8, Native: "Personal", Tagged: []string{"media"},
	}, false)
	if err != nil {
		t.Fatalf("apply create: %v", err)
	}
	if res.Outcome != "created_and_bound" || res.ProfileID == "" || res.ProfileName != "Personal+trunk(1)" || !res.ProfileCreate {
		t.Fatalf("create = %+v", res)
	}
	created := findTestProfile(st.Profiles, res.ProfileID)
	if created == nil {
		t.Fatalf("created profile %q not in state", res.ProfileID)
	}
	if created.NativeNetworkID != "n4" || len(created.TagNetworkIDs) != 1 || created.TagNetworkIDs[0] != "n3" ||
		len(created.UntagNetworkIDs) != 1 || created.UntagNetworkIDs[0] != "n4" {
		t.Errorf("created membership = %+v", created)
	}
	if created.PoE != 2 || created.Dot1x != 2 || created.BandWidthCtrlType != 0 ||
		created.PortIsolationEnable || created.LLDPMEDEnable || created.SpanningTreeEnable || created.LoopbackDetectEnable {
		t.Errorf("created defaults = %+v, want PoE=2 Dot1x=2 BW=0 bools false", created)
	}
	if st.PortProfiles[8] != res.ProfileID {
		t.Errorf("port 8 profile = %q, want %q", st.PortProfiles[8], res.ProfileID)
	}
	if !strings.Contains(res.Before, `"P1"`) || !strings.Contains(res.After, res.ProfileID) {
		t.Errorf("evidence before=%s after=%s", res.Before, res.After)
	}

	// Re-apply the same request: the newly bound profile now matches →
	// unchanged (idempotent).
	res, err = svc.ApplyPortProfile(ctx, opts, OmadaPortProfileRequest{
		SwitchMAC: coreMAC, Port: 8, Native: "Personal", Tagged: []string{"media"},
	}, false)
	if err != nil {
		t.Fatalf("re-apply: %v", err)
	}
	if res.Outcome != "unchanged" || res.ProfileID != created.ID {
		t.Errorf("re-apply = outcome %q profile %q, want unchanged/%s", res.Outcome, res.ProfileID, created.ID)
	}
}

func TestOmadaServiceApplyPortProfile_DryRun(t *testing.T) {
	st := omadaPortStateFresh()
	ts := omadaTestServer(t, omadaPortBaseHandler(t, st))
	res, err := NewOmadaService().ApplyPortProfile(context.Background(), omadaPortOpts(ts.URL),
		OmadaPortProfileRequest{SwitchMAC: "bb:11:22:33:44:55", Port: 8, Native: "Personal", Tagged: []string{"media"}},
		true)
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	// A dry run previews the real-apply outcome vocabulary.
	if !res.DryRun || res.Outcome != "created_and_bound" || !res.ProfileCreate || res.ProfileID != "" || res.ProfileName != "Personal+trunk(1)" {
		t.Errorf("dry run = %+v", res)
	}
	if len(st.Profiles) != 3 || st.PortProfiles[8] != "P1" {
		t.Errorf("dry run mutated state: profiles=%d port8=%q", len(st.Profiles), st.PortProfiles[8])
	}
	if res.Before == "" || res.Before != res.After {
		t.Errorf("dry run evidence = before %q after %q", res.Before, res.After)
	}
}

func TestOmadaServiceApplyPortProfile_Errors(t *testing.T) {
	st := omadaPortStateFresh()
	ts := omadaTestServer(t, omadaPortBaseHandler(t, st))
	svc := NewOmadaService()
	ctx := context.Background()
	opts := omadaPortOpts(ts.URL)

	_, err := svc.ApplyPortProfile(ctx, opts, OmadaPortProfileRequest{
		SwitchMAC: "bb:11:22:33:44:55", Port: 42, Native: "trusted",
	}, false)
	if err == nil || !strings.Contains(err.Error(), "port 42 not found on switch") {
		t.Errorf("missing port: err = %v", err)
	}

	_, err = svc.ApplyPortProfile(ctx, opts, OmadaPortProfileRequest{
		SwitchMAC: "bb:11:22:33:44:55", Port: 8, Native: "Nope",
	}, false)
	if err == nil || !strings.Contains(err.Error(), `network "Nope" is not a declared LAN network`) {
		t.Errorf("unknown network: err = %v", err)
	}
	if len(st.Profiles) != 3 {
		t.Errorf("failed apply created profiles: %d", len(st.Profiles))
	}

	ts2 := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		default:
			writeOmadaEnvelope(w, -33004, `null`)
		}
	})
	_, err = svc.ApplyPortProfile(ctx, omadaPortOpts(ts2.URL), OmadaPortProfileRequest{
		SwitchMAC: "bb:11:22:33:44:55", Port: 8, Native: "trusted",
	}, false)
	if err == nil {
		t.Error("expected fetch failure to propagate from apply")
	}
}

// TestOmadaServiceApplyPortProfile_BindFailureAfterCreate covers the
// create-then-bind path where the create succeeds and the bind fails: the
// error must name the created profile so the (reusable) site state change
// is visible to the caller.
func TestOmadaServiceApplyPortProfile_BindFailureAfterCreate(t *testing.T) {
	st := omadaPortStateFresh()
	st.FailBind = true
	ts := omadaTestServer(t, omadaPortBaseHandler(t, st))
	_, err := NewOmadaService().ApplyPortProfile(context.Background(), omadaPortOpts(ts.URL),
		OmadaPortProfileRequest{SwitchMAC: "bb:11:22:33:44:55", Port: 8, Native: "Personal", Tagged: []string{"gaming"}}, false)
	// The derived name for one tagged member is "Personal+trunk(1)".
	if err == nil || !strings.Contains(err.Error(), `LAN profile "Personal+trunk(1)" (id P101) was created but binding it failed`) {
		t.Fatalf("bind failure after create: err = %v", err)
	}
	// The orphan profile exists in the site state; a retry reuses it.
	if len(st.Profiles) != 4 || st.Profiles[3].ID != "P101" {
		t.Errorf("profile not created: %+v", st.Profiles)
	}
}

// TestOmadaServiceApplyPortProfile_MidApplyFailures exercises the two
// failure branches after a successful plan: a failed profile create and a
// failed ports-overview re-read after the bind.
func TestOmadaServiceApplyPortProfile_MidApplyFailures(t *testing.T) {
	// Create fails: the controller rejects the new profile before any bind.
	stCreate := omadaPortStateFresh()
	stCreate.FailCreateProfile = true
	ts := omadaTestServer(t, omadaPortBaseHandler(t, stCreate))
	_, err := NewOmadaService().ApplyPortProfile(context.Background(), omadaPortOpts(ts.URL),
		OmadaPortProfileRequest{SwitchMAC: "bb:11:22:33:44:55", Port: 8, Native: "Personal", Tagged: []string{"media"}}, false)
	if err == nil || !strings.Contains(err.Error(), "creating LAN profile") {
		t.Fatalf("create failure: err = %v, want create error", err)
	}
	if len(stCreate.Profiles) != 3 || stCreate.PortProfiles[8] != "P1" {
		t.Errorf("state after failed create: profiles=%d port8=%q, want unchanged", len(stCreate.Profiles), stCreate.PortProfiles[8])
	}

	// Re-read fails: the bind succeeds but the after-evidence fetch errors.
	// The plan read is the only overview GET before the apply's re-read, so
	// the second overview GET is the post-apply one.
	stReread := omadaPortStateFresh()
	stReread.OverviewFailAfter = 2
	ts2 := omadaTestServer(t, omadaPortBaseHandler(t, stReread))
	res, err := NewOmadaService().ApplyPortProfile(context.Background(), omadaPortOpts(ts2.URL),
		OmadaPortProfileRequest{SwitchMAC: "bb:11:22:33:44:55", Port: 8, Native: "Personal", Tagged: []string{"media"}}, false)
	if err == nil || !strings.Contains(err.Error(), "re-reading port state after apply") {
		t.Fatalf("re-read failure: res = %+v, err = %v, want re-read error", res, err)
	}
	if stReread.PortProfiles[8] == "P1" {
		t.Error("bind did not run: port 8 still bound to P1")
	}
}

func TestResolveNetworkIDList(t *testing.T) {
	nets := []omadabackend.Network{
		{ID: "n1", Name: "trusted"},
		{ID: "n2", Name: "Guest"},
		{ID: "n3", Name: "guest"},
	}

	if id, err := resolveNetworkIDList(nets, []string{"TRUSTED"}); err != nil || len(id) != 1 || id[0] != "n1" {
		t.Errorf("case-insensitive resolve = %v, %v", id, err)
	}
	if id, err := resolveNetworkIDList(nets, []string{"n2"}); err != nil || len(id) != 1 || id[0] != "n2" {
		t.Errorf("raw id passthrough = %v, %v", id, err)
	}

	// A shared display name fails closed with the candidate IDs, never a
	// first-match coin flip.
	_, err := resolveNetworkIDList(nets, []string{"guest"})
	if err == nil || !strings.Contains(err.Error(), `network name "guest" is ambiguous`) ||
		!strings.Contains(err.Error(), "n2") || !strings.Contains(err.Error(), "n3") {
		t.Errorf("duplicate name: err = %v", err)
	}

	// A raw ID is never ambiguous, even when its network shares a name.
	if id, err := resolveNetworkIDList(nets, []string{"n3"}); err != nil || id[0] != "n3" {
		t.Errorf("raw id of ambiguous-named network = %v, %v", id, err)
	}

	// Three same-name networks: the candidate list must contain each ID
	// exactly once (no double-count of the first match).
	three := append([]omadabackend.Network{}, nets...)
	three = append(three, omadabackend.Network{ID: "n4", Name: "GUEST"})
	_, err = resolveNetworkIDList(three, []string{"guest"})
	if err == nil {
		t.Fatalf("three same-name networks: expected an error, got nil")
	}
	for _, id := range []string{"n2", "n3", "n4"} {
		if !strings.Contains(err.Error(), id) {
			t.Errorf("three same-name networks: error %q missing candidate %s", err, id)
		}
	}
	if strings.Count(err.Error(), "(ids ") != 1 || !strings.Contains(err.Error(), "3 declared networks share it") {
		t.Errorf("three same-name networks: error = %v", err)
	}
}

func TestPlanPort_AmbiguousNativeName(t *testing.T) {
	st := omadaPortStateFresh()
	// Two declared networks share the display name "guest".
	nets := strings.Replace(omadaPortNets, `"name":"Personal"`, `"name":"guest"`, 1)
	nets = strings.Replace(nets, `"name":"trusted"`, `"name":"guest"`, 1)
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/openapi/v1/abc123/sites/s1/lan-networks":
			writeOmadaEnvelope(w, 0, `{"totalRows":4,"data":`+nets+`}`)
		case "/openapi/v1/abc123/sites/s1/switches/ports/overview":
			writePortOverview(w, st)
		case "/openapi/v1/abc123/sites/s1/lan-profiles":
			writeOmadaEnvelope(w, 0, `{"totalRows":`+strconv.Itoa(len(st.Profiles))+`,"data":`+string(mustMarshalJSON(st.Profiles))+`}`)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	_, err := NewOmadaService().PlanPort(context.Background(), omadaPortOpts(ts.URL),
		OmadaPortProfileRequest{SwitchMAC: "bb:11:22:33:44:55", Port: 8, Native: "guest"})
	if err == nil || !strings.Contains(err.Error(), `network name "guest" is ambiguous`) {
		t.Errorf("plan with duplicate native name: err = %v", err)
	}
}

// TestPlanPort_ProfileOverrideWarning covers a port whose effective
// membership may differ from the bound profile: the plan still reports the
// bound-profile outcome, but it must carry the override warning so the
// agent knows the port needs re-verification.
func TestPlanPort_ProfileOverrideWarning(t *testing.T) {
	st := omadaPortStateFresh()
	st.Port8Override = true
	ts := omadaTestServer(t, omadaPortBaseHandler(t, st))
	plan, err := NewOmadaService().PlanPort(context.Background(), omadaPortOpts(ts.URL),
		OmadaPortProfileRequest{SwitchMAC: "bb:11:22:33:44:55", Port: 8, Native: "trusted"})
	if err != nil {
		t.Fatalf("PlanPort: %v", err)
	}
	if plan.Outcome != "unchanged" {
		t.Fatalf("plan outcome = %q, want unchanged", plan.Outcome)
	}
	if len(plan.Warnings) != 1 || !strings.Contains(plan.Warnings[0], "profile override") {
		t.Errorf("plan warnings = %v, want the profile-override warning", plan.Warnings)
	}
	if plan.Current == nil || !plan.Current.ProfileOverride {
		t.Errorf("plan current = %+v, want ProfileOverride true", plan.Current)
	}

	// The warning must travel into the apply result: an "unchanged"
	// short-circuit on an overridden port is only valid after the port is
	// re-verified.
	res, err := NewOmadaService().ApplyPortProfile(context.Background(), omadaPortOpts(ts.URL),
		OmadaPortProfileRequest{SwitchMAC: "bb:11:22:33:44:55", Port: 8, Native: "trusted"}, true)
	if err != nil {
		t.Fatalf("ApplyPortProfile: %v", err)
	}
	if res.Outcome != "unchanged" {
		t.Fatalf("apply outcome = %q, want unchanged", res.Outcome)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "profile override") {
		t.Errorf("apply warnings = %v, want the profile-override warning", res.Warnings)
	}
}

func TestOmadaServiceListLanProfiles_NetworksFetchFails(t *testing.T) {
	st := omadaPortStateFresh()
	// The profiles read succeeds; the networks read that resolves their
	// names fails, so a partial picture must surface as an error.
	st.NetworksFailAfter = 1
	ts := omadaTestServer(t, omadaPortBaseHandler(t, st))
	if _, err := NewOmadaService().ListLanProfiles(context.Background(), omadaPortOpts(ts.URL)); err == nil {
		t.Fatal("expected lan-networks fetch failure to propagate")
	}
}

// TestOmadaServicePlanPort_MembershipFetchFails: a failure on the second
// or third collection read inside fetchPortMembership must fail the plan,
// matching the behavior asserted for ListSwitchPorts.
func TestOmadaServicePlanPort_MembershipFetchFails(t *testing.T) {
	for name, mutate := range map[string]func(*omadaPortState){
		"lan-profiles": func(st *omadaPortState) { st.ProfilesFailAfter = 1 },
		"lan-networks": func(st *omadaPortState) { st.NetworksFailAfter = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			st := omadaPortStateFresh()
			mutate(st)
			ts := omadaTestServer(t, omadaPortBaseHandler(t, st))
			_, err := NewOmadaService().PlanPort(context.Background(), omadaPortOpts(ts.URL),
				OmadaPortProfileRequest{SwitchMAC: "bb:11:22:33:44:55", Port: 8, Native: "trusted"})
			if err == nil {
				t.Fatal("expected membership fetch failure to propagate")
			}
		})
	}
}

// TestOmadaServiceApplyPortProfile_DryRunRebind: a dry run must preview the
// real-apply outcome vocabulary for a rebind — the port would end up
// bound to the existing matching profile without a create.
func TestOmadaServiceApplyPortProfile_DryRunRebind(t *testing.T) {
	st := omadaPortStateFresh()
	ts := omadaTestServer(t, omadaPortBaseHandler(t, st))
	res, err := NewOmadaService().ApplyPortProfile(context.Background(), omadaPortOpts(ts.URL),
		OmadaPortProfileRequest{
			SwitchMAC: "AA:BB:CC:DD:EE:01", Port: 10, Native: "media", Tagged: []string{"trusted", "gaming"},
		}, true)
	if err != nil {
		t.Fatalf("dry run rebind: %v", err)
	}
	if !res.DryRun || res.Outcome != "bound" || res.ProfileID != "P3" || res.ProfileCreate {
		t.Errorf("dry run = %+v, want outcome bound / profile P3 / no create", res)
	}
	if st.PortProfiles[10] != "P1" || len(st.Profiles) != 3 {
		t.Errorf("dry run mutated state: port10=%q profiles=%d", st.PortProfiles[10], len(st.Profiles))
	}
}

// TestOmadaServiceApplyPortProfile_BindFailureWithoutCreate: a bind
// failure on a rebind (no profile create) must surface the raw bind error.
func TestOmadaServiceApplyPortProfile_BindFailureWithoutCreate(t *testing.T) {
	st := omadaPortStateFresh()
	st.FailBind = true
	ts := omadaTestServer(t, omadaPortBaseHandler(t, st))
	_, err := NewOmadaService().ApplyPortProfile(context.Background(), omadaPortOpts(ts.URL),
		OmadaPortProfileRequest{
			SwitchMAC: "AA:BB:CC:DD:EE:01", Port: 10, Native: "media", Tagged: []string{"trusted", "gaming"},
		}, false)
	if err == nil {
		t.Fatal("expected bind failure to propagate")
	}
	if strings.Contains(err.Error(), "was created but binding") {
		t.Errorf("error = %v, want the raw bind error, not the create-then-bind wrapper", err)
	}
	if st.PortProfiles[10] != "P1" || len(st.Profiles) != 3 {
		t.Errorf("state = port10 %q / %d profiles, want unchanged", st.PortProfiles[10], len(st.Profiles))
	}
}

// TestOmadaServicePlanPort_UnknownTaggedName: an unknown network name in
// the tagged list must fail closed, like an unknown native name does.
func TestOmadaServicePlanPort_UnknownTaggedName(t *testing.T) {
	st := omadaPortStateFresh()
	ts := omadaTestServer(t, omadaPortBaseHandler(t, st))
	_, err := NewOmadaService().PlanPort(context.Background(), omadaPortOpts(ts.URL),
		OmadaPortProfileRequest{SwitchMAC: "bb:11:22:33:44:55", Port: 8, Native: "trusted", Tagged: []string{"Nope"}})
	if err == nil || !strings.Contains(err.Error(), `network "Nope" is not a declared LAN network`) {
		t.Errorf("unknown tagged: err = %v", err)
	}
}

func TestDerivePortProfileName(t *testing.T) {
	if got := derivePortProfileName(OmadaPortProfileRequest{Native: "media"}); got != "media" {
		t.Errorf("zero tagged = %q, want the native name", got)
	}
	if got := derivePortProfileName(OmadaPortProfileRequest{Native: "media", Tagged: []string{"trusted", "gaming"}}); got != "media+trunk(2)" {
		t.Errorf("two tagged = %q, want media+trunk(2)", got)
	}
}

// TestPortEvidenceJSON_NotFound: a port that is no longer in the overview
// (e.g. between plan and re-read) yields empty JSON evidence rather than
// an error.
func TestPortEvidenceJSON_NotFound(t *testing.T) {
	ports := []omadabackend.SwitchPort{{Port: 1, SwitchMAC: "aa:bb:cc:dd:ee:01"}}
	out, err := portEvidenceJSON(ports, nil, nil, "bb:11:22:33:44:55", 8)
	if err != nil || out != "{}" {
		t.Errorf("portEvidenceJSON = %q, %v, want {} / nil", out, err)
	}
}

func TestResolveNetworkIDs_Fallback(t *testing.T) {
	netName := networkNameByID([]omadabackend.Network{{ID: "n1", Name: "trusted"}})
	if got := resolveNetworkIDs([]string{"n1", "nX"}, netName); len(got) != 2 || got[0] != "trusted" || got[1] != "nX" {
		t.Errorf("resolveNetworkIDs = %v, want [trusted nX]", got)
	}
}

func TestFindProfileByID(t *testing.T) {
	profiles := []omadabackend.LanProfile{{ID: "P1", Name: "a"}, {ID: "P2", Name: "b"}}
	if p := findProfileByID(profiles, "P2"); p == nil || p.Name != "b" {
		t.Errorf("findProfileByID = %+v, want P2", p)
	}
	if p := findProfileByID(profiles, "P9"); p != nil {
		t.Errorf("findProfileByID miss = %+v, want nil", p)
	}
}

// findTestProfile returns one stored profile by ID, or nil.
func findTestProfile(profiles []omadabackend.LanProfile, id string) *omadabackend.LanProfile {
	for i := range profiles {
		if profiles[i].ID == id {
			return &profiles[i]
		}
	}
	return nil
}

func TestPortRevisionGuardsInterveningChange(t *testing.T) {
	st := omadaPortStateFresh()
	ts := omadaTestServer(t, omadaPortBaseHandler(t, st))
	s := NewOmadaService()
	opts := omadaPortOpts(ts.URL)
	desired := OmadaPortProfileRequest{SwitchMAC: "bb:11:22:33:44:55", Port: 8, Native: "media", Tagged: []string{"gaming"}}
	plan, err := s.PlanPort(t.Context(), opts, desired)
	if err != nil || plan.Revision == "" {
		t.Fatalf("initial plan: %v", err)
	}
	desired.ExpectedRevision = plan.Revision
	if _, err := s.ApplyPortProfile(t.Context(), opts, desired, true); err != nil {
		t.Fatalf("unchanged revision: %v", err)
	}
	st.Port8Override = !st.Port8Override
	count := len(st.Profiles)
	binding := st.PortProfiles[8]
	if _, err := s.ApplyPortProfile(t.Context(), opts, desired, false); err == nil || !strings.Contains(err.Error(), "changed since the plan") {
		t.Fatalf("intervening override: %v", err)
	}
	if len(st.Profiles) != count || st.PortProfiles[8] != binding {
		t.Error("conflict mutated controller")
	}
}

func TestManagedPortVerificationAndSharedClients(t *testing.T) {
	st := omadaPortStateFresh()
	base := omadaPortBaseHandler(t, st)
	const a = "02:aa:bb:cc:dd:04"
	const b = "02:aa:bb:cc:dd:05"
	const sw = "bb:11:22:33:44:55"
	port := "8"
	lease := true
	clients := `[{"mac":"` + a + `"},{"mac":"` + b + `"}]`
	ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/networks/client"):
			writeOmadaEnvelope(w, 0, clients)
		case strings.HasSuffix(r.URL.Path, "/lldp-neighbors"), strings.HasSuffix(r.URL.Path, "/networks/devices"):
			writeOmadaEnvelope(w, 0, `[]`)
		case strings.HasSuffix(r.URL.Path, "/client-link-topology"):
			mac := a
			if strings.Contains(r.URL.Path, "dd-05/") {
				mac = b
			}
			writeOmadaEnvelope(w, 0, `[{"nodeType":"clientNode","clientNode":{"mac":"`+mac+`","upOswInfo":{"mac":"`+sw+`","port":"`+port+`"}}}]`)
		case strings.HasSuffix(r.URL.Path, "/dhcp/user-list"):
			rows := "[]"
			if lease {
				rows = `[{"macAddress":"` + a + `","ipAddress":"10.0.10.10","netId":"n1"}]`
			}
			writeOmadaEnvelope(w, 0, rows)
		default:
			base(w, r)
		}
	})
	svc := NewOmadaService()
	opts := omadaPortOpts(ts.URL)
	ctx := t.Context()
	c, site, err := svc.session(ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Logout(ctx)
	occupancy, ok := switchClients(ctx, c, site.EffectiveID(), omadabackend.NormalizeMAC(sw))
	if !ok || len(occupancy[8]) != 2 {
		t.Fatalf("shared port: %v %v", occupancy, ok)
	}
	req := OmadaPortProfileRequest{SwitchMAC: sw, Port: 8, Native: "trusted", VerifyClientMAC: a}
	plan, err := svc.PlanPort(ctx, opts, req)
	if err != nil {
		t.Fatal(err)
	}
	req.ExpectedRevision = plan.Revision
	apply := func() *PortVerification {
		t.Helper()
		result, err := svc.ApplyPortProfile(ctx, opts, req, false)
		if err != nil || result.Verification == nil {
			t.Fatalf("guarded apply: %v", err)
		}
		return result.Verification
	}
	if v := apply(); v.Membership != "observed" || v.Connectivity != "attached" || v.DHCP != "lease on desired native network" {
		t.Fatalf("wrong post-apply evidence %+v", v)
	}
	port = "9"
	lease = false
	if v := apply(); v.Membership != "observed" || v.Connectivity != "different attachment" || v.DHCP != "unverified" {
		t.Fatalf("unknown DHCP/changed attachment: %+v", v)
	}
	port = "8"
	clients = `[{"mac":"` + a + `"}]`
	attachment, err := readPortAttachments(ctx, c, site.EffectiveID(), sw)
	if err != nil || !attachment[8].matches("access", a, nil) {
		t.Fatalf("single attachment: %v", err)
	}
	req.ExpectedRevision, err = attachment[8].revision(plan.Revision)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ApplyPortProfile(ctx, opts, req, true); err != nil {
		t.Fatalf("current attachment guard: %v", err)
	}
	clients = `[{"mac":"` + a + `"},{"mac":"` + b + `"}]`
	if _, err := svc.ApplyPortProfile(ctx, opts, req, false); err == nil || !strings.Contains(err.Error(), "changed since") {
		t.Fatal("changed occupants accepted", err)
	}

}
