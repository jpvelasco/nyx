package service

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestOmadaACLOrder(t *testing.T) {
	for _, scope := range []string{"gateway", "switch", "eap"} {
		t.Run(scope, func(t *testing.T) {
			rows := []map[string]any{{"id": "permit-dns", "index": 7}, {"id": "deny-rest", "index": 19}}
			writes := 0
			server := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/openapi/authorize/token":
					writeOmadaEnvelope(w, 0, `{"accessToken":"fixture"}`)
				case "/openapi/v1/abc123/sites":
					writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"example"}]}`)
				case "/openapi/v1/abc123/sites/s1/acls/" + map[string]string{"gateway": "osg-acls", "switch": "osw-acls", "eap": "eap-acls"}[scope]:
					_ = json.NewEncoder(w).Encode(map[string]any{"errorCode": 0, "result": map[string]any{"totalRows": len(rows), "data": rows}})
				case "/openapi/v1/abc123/sites/s1/acls/modifyIndex":
					writes++
					var v struct {
						Type    string
						Indexes map[string]int
					}
					if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
						t.Error(err)
					}
					if r.Method != "POST" || v.Type != scope || v.Indexes["deny-rest"] != 7 || v.Indexes["permit-dns"] != 19 {
						t.Error("wrong enforcement point or index")
					}
					rows[0]["index"] = 19
					rows[1]["index"] = 7
					// The controller saved the order but its reply was lost.
					http.Error(w, "lost response", http.StatusBadGateway)
				default:
					http.NotFound(w, r)
				}
			})
			opts := omadaPortOpts(server.URL)
			opts.Site = "example"
			svc := NewOmadaService()
			req := OmadaACLOrderRequest{Scope: scope, Expected: []string{"permit-dns", "deny-rest"}, Desired: []string{"deny-rest", "permit-dns"}}
			preview, err := svc.ACLOrder(t.Context(), opts, req, true)
			if err != nil || preview.Outcome != "reorder" || preview.Before[0].ID != "permit-dns" || preview.After[0].ID != "deny-rest" || writes != 0 {
				t.Fatalf("preview %+v %v", preview, err)
			}
			stale := req
			stale.Expected = []string{"obsolete"}
			if _, err := svc.ACLOrder(t.Context(), opts, stale, false); err == nil || !strings.Contains(err.Error(), "changed") || writes != 0 {
				t.Fatalf("stale %v writes=%d", err, writes)
			}
			duplicate := req
			duplicate.Desired = []string{"deny-rest", "deny-rest"}
			if _, err := svc.ACLOrder(t.Context(), opts, duplicate, false); err == nil || writes != 0 {
				t.Fatalf("invalid permutation %v writes=%d", err, writes)
			}
			changed, err := svc.ACLOrder(t.Context(), opts, req, false)
			if err != nil || changed.Outcome != "reordered" || writes != 1 {
				t.Fatalf("apply %+v %v writes=%d", changed, err, writes)
			}
			repeat, err := svc.ACLOrder(t.Context(), opts, req, false)
			if err != nil || repeat.Outcome != "unchanged" || writes != 1 {
				t.Fatalf("retry %+v %v writes=%d", repeat, err, writes)
			}
			rows[0]["index"] = 7
			if _, err := svc.ACLOrder(t.Context(), opts, req, false); err == nil || writes != 1 {
				t.Fatalf("duplicate index %v writes=%d", err, writes)
			}
		})
	}
}

func TestACLOrderRequiresVerifiedReadback(t *testing.T) {
	for _, readDenied := range []bool{false, true} {
		writes := 0
		server := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.URL.Path == "/openapi/authorize/token":
				writeOmadaEnvelope(w, 0, `{"accessToken":"fixture"}`)
			case strings.HasSuffix(r.URL.Path, "/sites"):
				writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"example"}]}`)
			case strings.HasSuffix(r.URL.Path, "/modifyIndex"):
				writes++
				writeOmadaEnvelope(w, 0, `{}`)
			case strings.HasSuffix(r.URL.Path, "/osw-acls"):
				if writes > 0 && readDenied {
					http.Error(w, "denied", http.StatusForbidden)
					return
				}
				writeOmadaEnvelope(w, 0, `{"totalRows":2,"data":[{"id":"a","index":1},{"id":"b","index":2}]}`)
			default:
				http.NotFound(w, r)
			}
		})
		opts := omadaPortOpts(server.URL)
		opts.Site = "example"
		svc := NewOmadaService()
		req := OmadaACLOrderRequest{Scope: "switch"}
		if res, err := svc.ACLOrder(t.Context(), opts, req, true); err != nil || len(res.Before) != 2 {
			t.Fatalf("read: %v %v", res, err)
		}
		if _, err := svc.ACLOrder(t.Context(), opts, req, false); err == nil {
			t.Fatal("applied without preview")
		}
		req.Desired = []string{"b"}
		if _, err := svc.ACLOrder(t.Context(), opts, req, true); err == nil {
			t.Fatal("accepted partial order")
		}
		req.Expected = []string{"a", "b"}
		req.Desired = []string{"b", "a"}
		if _, err := svc.ACLOrder(t.Context(), opts, req, false); err == nil || writes != 1 {
			t.Fatalf("unverified apply: %v, writes=%d", err, writes)
		}
	}
	if _, err := NewOmadaService().ACLOrder(t.Context(), OmadaOptions{}, OmadaACLOrderRequest{Scope: "other"}, true); err == nil {
		t.Fatal("accepted unknown scope")
	}
}
