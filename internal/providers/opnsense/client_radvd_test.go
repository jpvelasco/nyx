package opnsense

import (
	"github.com/jpvelasco/nyx/internal/testutil"
	"net/http"
	"testing"
)

func TestRouterAdvertisementVisibility(t *testing.T) {
	for _, tc := range []struct {
		label, body string
		code, count int
		expected    []string
	}{
		{"observed", `{"total":3,"rows":[{"interface":"opt1","enabled":"1","mode":"managed"},{"interface":"opt2","enabled":"0","mode":"stateless"},{"interface":"opt3"}]}`, 200, 3, []string{"enabled", "disabled", "unknown"}},
		{"empty", `{"total":0,"rows":[]}`, 200, 0, nil}, {"missing rows", `{}`, 200, -1, nil}, {"partial", `{"total":2,"rows":[]}`, 200, -1, nil}, {"malformed", `{"rows":[{}]}`, 200, -1, nil}, {"unavailable", `{}`, 403, -1, nil},
	} {
		t.Run(tc.label, func(t *testing.T) {
			c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/api/radvd/settings/search_entry" {
					t.Fatal("unexpected RADVD request")
				}
				w.WriteHeader(tc.code)
				testutil.WriteBody(w, tc.body)
			}))
			got, err := c.GetRouterAdvertisements(t.Context())
			if tc.count < 0 {
				if err == nil {
					t.Fatal("unavailable configuration reported as empty")
				}
				return
			}
			if err != nil || len(got) != tc.count {
				t.Fatalf("got %+v, %v", got, err)
			}
			for i, want := range tc.expected {
				if got[i].State != want {
					t.Fatalf("got %+v", got[i])
				}
			}
		})
	}
}

func TestKeaStatusUnknownAndNested(t *testing.T) {
	for _, tc := range []struct {
		body        string
		want, known bool
	}{{`{"status":{"kea":"running"}}`, true, true}, {`{"kea":{"status":"stopped"}}`, false, true}, {`{"unrelated":"ok"}`, false, false}, {`{"running":"unknown"}`, false, false}} {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { testutil.WriteBody(w, tc.body) }))
		got, err := c.GetKeaServiceStatus(t.Context())
		if (err == nil) != tc.known || got != tc.want {
			t.Fatalf("unrecognized Kea state result %t, %v", got, err)
		}
	}
}
