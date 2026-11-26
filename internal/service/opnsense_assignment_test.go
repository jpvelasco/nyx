package service

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	fw "github.com/jpvelasco/nyx/internal/providers/opnsense"
	"github.com/jpvelasco/nyx/internal/testutil"
)

func TestVLANAssignmentLifecycle(t *testing.T) {
	for _, tc := range []struct{ name, address, family, field, activation string }{
		{"ipv4", "10.0.30.1/24", "type4", "ipaddr", "ok"},
		{"ipv6", "2001:db8::1/64", "type6", "ipaddrv6", "ok"},
		{"lost response", "10.0.30.1/24", "type4", "ipaddr", "lost"},
		{"still staged", "10.0.30.1/24", "type4", "ipaddr", "staged"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var rows []map[string]string
			pending := "ok"
			var adds, applies int
			server := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/diagnostics/interface/get_routes":
					testutil.WriteBody(w, `[{"destination":"default","netif":"igb0"},{"destination":"fe80::%igb0/64","netif":"igb0"}]`)
				case "/api/interfaces/vlan_settings/search_item":
					testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"v1","if":"igb0","tag":"30","vlanif":"vlan30"}]}`)
				case "/api/interfaces/assignment/search_item":
					if rows == nil {
						rows = []map[string]string{}
					}
					_ = json.NewEncoder(w).Encode(map[string]any{"total": len(rows), "rows": rows})
				case "/api/interfaces/assignment/pending":
					_ = json.NewEncoder(w).Encode(map[string]string{"status": pending})
				case "/api/interfaces/assignment/add_item":
					adds++
					var data struct {
						Interface map[string]string `json:"interface"`
					}
					if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
						t.Error(err)
					}
					row := data.Interface
					if r.Method != "POST" || row[tc.field] != tc.address || row[tc.family] != "staticv"+tc.family[4:] || row["if"] != "vlan30" || row["descr"] != "gaming" || len(row) != 5 {
						t.Errorf("wrong write fields %v", row)
					}
					row["identifier"] = "opt3"
					row["pending_action"] = "update"
					rows = append(rows, row)
					pending = "pending"
					testutil.WriteBody(w, `{"result":"saved","uuid":"opt3"}`)
				case "/api/interfaces/assignment/reconfigure":
					applies++
					if tc.activation == "staged" {
						http.Error(w, "busy", http.StatusServiceUnavailable)
						return
					}
					rows[0]["pending_action"] = ""
					pending = "ok"
					if tc.activation == "lost" {
						http.Error(w, "response lost", http.StatusServiceUnavailable)
						return
					}
					testutil.WriteBody(w, `{"status":"ok"}`)
				default:
					http.NotFound(w, r)
				}
			})
			req := OpnsenseVLANRequest{Kind: "assignment", Parent: "igb0", Tag: 30, Description: "gaming", Address: tc.address}
			s := NewOpnsenseService()
			ctx := t.Context()
			opts := opnsenseOptions(server)
			preview, err := s.ApplyVLAN(ctx, opts, req, true)
			if err != nil || preview.Outcome != "assign" || !preview.DryRun || adds != 0 {
				t.Fatalf("preview %v %v adds=%d", preview, err, adds)
			}
			applied, err := s.ApplyVLAN(ctx, opts, req, false)
			if tc.activation == "staged" {
				if err == nil || !strings.Contains(err.Error(), "uncertain") {
					t.Fatalf("unconfirmed activation: %v", err)
				}
			} else if err != nil || applied.Outcome != "assigned" || applied.UUID != "opt3" {
				t.Fatalf("apply %v %v", applied, err)
			}
			again, err := s.ApplyVLAN(ctx, opts, req, false)
			expected := "unchanged"
			if tc.activation == "staged" {
				expected = "manual"
			}
			if err != nil || again.Outcome != expected || adds != 1 || applies != 1 {
				t.Fatalf("retry %v %v adds=%d applies=%d", again, err, adds, applies)
			}
		})
	}
}

func TestVLANAssignmentPreflight(t *testing.T) {
	const empty = `{"total":0,"rows":[]}`
	const oneVLAN = `{"total":1,"rows":[{"uuid":"v1","if":"igb0","tag":"30","vlanif":"vlan30 [gaming]"}]}`
	for _, tc := range []struct {
		name, grid, pending, routes, wantAction, wantErr string
		code                                             int
	}{
		{name: "older firewall", code: 404, wantAction: "manual"},
		{name: "missing privilege", code: 403, wantErr: "permission denied"},
		{name: "incomplete", grid: `{"total":1,"rows":[]}`, wantErr: "incomplete"},
		{name: "pending queue", grid: empty, pending: "pending", wantAction: "manual"},
		{name: "unrecognized status", grid: empty, pending: "unknown", wantErr: "pending status"},
		{name: "assigned to management", grid: `{"total":1,"rows":[{"identifier":"lan","if":"vlan30","descr":"management"}]}`, wantErr: "conflicts"},
		{name: "duplicate role", grid: `{"total":1,"rows":[{"identifier":"lan","if":"igb1","descr":"gaming"}]}`, wantErr: "conflicts"},
		{name: "existing subnet", grid: `{"total":1,"rows":[{"identifier":"lan","if":"igb1","ipaddr":"10.0.30.1/24"}]}`, wantErr: "overlaps another"},
		{name: "active route", grid: empty, routes: `[{"destination":"10.0.30.1"}]`, wantErr: "overlaps an active route"},
		{name: "route inventory missing", grid: empty, routes: `{}`, wantErr: "active routes"},
		{name: "bad route", grid: empty, routes: `[{"destination":"unknown"}]`, wantErr: "active route prefix"},
		{name: "malformed address", grid: `{"total":1,"rows":[{"identifier":"lan","if":"igb1","ipaddr":"unavailable"}]}`, wantErr: "existing interface address"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" {
					t.Errorf("unexpected mutation: %s", r.URL.Path)
					http.Error(w, "unexpected", 400)
					return
				}
				switch r.URL.Path {
				case "/api/interfaces/vlan_settings/search_item":
					testutil.WriteBody(w, oneVLAN)
				case "/api/interfaces/assignment/search_item":
					if tc.code != 0 {
						w.WriteHeader(tc.code)
						return
					}
					testutil.WriteBody(w, tc.grid)
				case "/api/interfaces/assignment/pending":
					pending := tc.pending
					if pending == "" {
						pending = "ok"
					}
					_ = json.NewEncoder(w).Encode(map[string]string{"status": pending})
				case "/api/diagnostics/interface/get_routes":
					testutil.WriteBody(w, tc.routes)
				default:
					t.Errorf("unexpected read: %s", r.URL.Path)
					http.NotFound(w, r)
				}
			})
			req := OpnsenseVLANRequest{Kind: "assignment", Parent: "igb0", Tag: 30, Description: "gaming", Address: "10.0.30.1/24"}
			got, err := NewOpnsenseService().ApplyVLAN(t.Context(), opnsenseOptions(s), req, false)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got.Outcome != tc.wantAction || got.Warning == "" {
				t.Fatalf("result %v %v", got, err)
			}
		})
	}
}

func TestAssignmentDoesNotActivateOtherChanges(t *testing.T) {
	old := fw.Assignment{Identifier: "lan", Device: "igb0"}
	added := fw.Assignment{Identifier: "opt3", Device: "vlan30", Pending: "update"}
	another := fw.Assignment{Identifier: "opt4", Device: "vlan40", Pending: "update"}
	before := assignmentView{rows: []fw.Assignment{old}}
	for _, after := range []assignmentView{{rows: []fw.Assignment{added}, pending: true}, {rows: []fw.Assignment{added, another}, pending: true}, {rows: []fw.Assignment{old, added}}, {rows: []fw.Assignment{old, another}, pending: true}} {
		if after.onlyAdded(before, "opt3") {
			t.Fatal("accepted unrelated or unconfirmed changes")
		}
	}
}

func TestAssignmentTargetRequiresUniqueExistingVLAN(t *testing.T) {
	req := OpnsenseVLANRequest{Kind: "assignment", Address: "10.0.30.1/24", Tag: 30, Parent: "igb0", Description: "gaming"}
	for _, view := range []string{
		`{"total":0,"rows":[]}`,
		`{"total":1,"rows":[{"uuid":"other","if":"igb1","tag":"40","vlanif":"vlan40"}]}`,
		`{"total":2,"rows":[{"uuid":"one","if":"igb0","tag":"30","vlanif":"vlan30"},{"uuid":"two","if":"igb0","tag":"30","vlanif":"vlan31"}]}`,
		`{"total":1,"rows":[{"uuid":"one","if":"igb0","tag":"30","vlanif":"igb0"}]}`,
	} {
		ts := opnsenseTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" || !strings.HasSuffix(r.URL.Path, "/vlan_settings/search_item") {
				t.Error("contacted a non-target surface")
			}
			testutil.WriteBody(w, view)
		})
		if _, err := NewOpnsenseService().ApplyVLAN(t.Context(), opnsenseOptions(ts), req, false); err == nil {
			t.Error("accepted missing or ambiguous VLAN identity")
		}
	}
	req.Tag = 0
	if _, err := assignmentTarget(t.Context(), nil, req); err == nil {
		t.Error("accepted tag zero")
	}
	req.Tag = 30
	req.Address = "0.0.0.0/0"
	if _, err := assignmentTarget(t.Context(), nil, req); err == nil {
		t.Error("accepted unspecified address")
	}
}

func TestAssignmentRejectsSubnetAndBroadcast(t *testing.T) {
	for _, addr := range []string{"192.0.2.0/24", "192.0.2.255/24"} {
		if _, err := assignmentTarget(t.Context(), nil, OpnsenseVLANRequest{Address: addr}); err == nil || !strings.Contains(err.Error(), "usable host") {
			t.Errorf("expected unusable address refusal for %s: %v", addr, err)
		}
	}
}
