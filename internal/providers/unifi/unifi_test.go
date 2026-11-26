package unifi

import (
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/testutil"
)

const siteID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
const switchID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
const apID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
const prefix = "/proxy/network/integration/v1"

func connection(host string) providers.ImportOptions {
	return providers.ImportOptions{Host: host, Credentials: map[string]string{"api_key": "fixture"}}
}

func TestOfficialInventoryAndUplink(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Header.Get("X-API-Key") != "fixture" {
			t.Error("unexpected method or credentials")
			return
		}
		switch r.URL.Path {
		case prefix + "/sites":
			testutil.WriteBody(w, `{"offset":0,"count":1,"totalCount":1,"data":[{"id":"`+siteID+`","name":"site"}]}`)
		case prefix + "/sites/" + siteID + "/devices":
			if r.URL.Query().Get("offset") == "0" {
				testutil.WriteBody(w, `{"offset":0,"count":1,"totalCount":2,"data":[{"id":"`+switchID+`","features":["switching"]}]}`)
			} else {
				testutil.WriteBody(w, `{"offset":1,"count":1,"totalCount":2,"data":[{"id":"`+apID+`","features":["accessPoint"]}]}`)
			}
		case prefix + "/sites/" + siteID + "/devices/" + switchID:
			testutil.WriteBody(w, `{"id":"`+switchID+`","interfaces":{"ports":[{"idx":1},{"idx":1}]}}`)
		case prefix + "/sites/" + siteID + "/devices/" + apID:
			testutil.WriteBody(w, `{"id":"`+apID+`","uplink":{"deviceId":"`+switchID+`"}}`)
		default:
			t.Error("unexpected integration resource")
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	opts := connection(server.URL)
	opts.CACertPath = filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(opts.CACertPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := (Adapter{}).ObserveNetwork(t.Context(), opts)
	if err != nil || len(got.Resources) != 3 || len(got.Links) != 2 || got.Links[1].Relation != "uplink" || got.Links[1].To.Ref.Key != switchID || !slices.Contains(got.Gaps, "port identity") {
		t.Fatalf("unexpected facts %+v %v", got, err)
	}
}

func TestInvalidPagesAndPrivateFailures(t *testing.T) {
	const valid = `{"offset":0,"count":1,"totalCount":1,"data":[{"id":"` + siteID + `"}]}`
	for _, page := range []string{strings.Replace(valid, siteID, "../sites", 1), strings.Replace(valid, `"count":1`, `"count":2`, 1), `{"offset":0,"count":0,"totalCount":1,"data":[]}`, `{`, strings.Replace(valid, `"offset":0`, `"offset":1`, 1)} {
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { testutil.WriteBody(w, page) }))
		opts := connection(s.URL)
		opts.SkipTLSVerify = true
		_, err := (Adapter{}).ObserveNetwork(t.Context(), opts)
		s.Close()
		if err == nil || strings.Contains(err.Error(), s.URL) {
			t.Fatalf("invalid inventory err=%v", err)
		}
	}
	for _, host := range []string{"http://unifi.example", "https://unifi.example/some/path", "https://key@unifi.example"} {
		if _, err := newClient(connection(host)); err == nil {
			t.Error("accepted invalid origin")
		}
	}
	opts := connection("https://unifi.example")
	opts.Credentials = nil
	if _, err := newClient(opts); err == nil {
		t.Error("accepted missing credentials")
	}
	sites := []identity{{ID: siteID, Name: "site"}, {ID: switchID, Name: "site"}}
	for _, name := range []string{"site", "absent", ""} {
		if _, err := siteFor(sites, name); err == nil {
			t.Error("accepted ambiguous site")
		}
	}
	if site, err := siteFor(sites, siteID); err != nil || site.ID != siteID {
		t.Fatal("site id did not select unique site")
	}
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("followed redirect") }))
	defer target.Close()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	opts = connection(origin.URL)
	opts.SkipTLSVerify = true
	_, err := (Adapter{}).ObserveNetwork(t.Context(), opts)
	var status statusError
	if !errors.As(err, &status) || status.HTTPStatus() != http.StatusTemporaryRedirect {
		t.Fatalf("redirect: %v", err)
	}
}
