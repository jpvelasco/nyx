package service

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestReadSiteConfig(t *testing.T) {
	for _, failure := range []bool{false, true} {
		ts := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/openapi/authorize/token":
				writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
			case strings.HasSuffix(r.URL.Path, "/sites"):
				writeOmadaEnvelope(w, 0, `[{"id":"site","name":"HQ"}]`)
			case strings.HasPrefix(r.URL.Path, "/openapi/v1/abc123/sites/site/"):
				if failure {
					writeOmadaEnvelope(w, -1005, "null")
					return
				}
				writeOmadaEnvelope(w, 0, `[]`)
			default:
				t.Errorf("unexpected path %s", r.URL.Path)
				http.NotFound(w, r)
			}
		})
		got, err := NewOmadaService().ReadSiteConfig(context.Background(), OmadaOptions{Host: ts.URL, SkipTLSVerify: true})
		if (err != nil) != failure || !failure && len(got.Resources) != 4 {
			t.Errorf("site configuration = %+v, %v; failure expected %t", got, err, failure)
		}
	}
}
