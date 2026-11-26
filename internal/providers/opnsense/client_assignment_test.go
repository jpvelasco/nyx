package opnsense

import (
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
)

func TestAssignmentInventoryWire(t *testing.T) {
	for _, tc := range []struct {
		body  string
		valid bool
	}{
		{`{"rows":[],"total":0}`, true},
		{`{"rows":[{"identifier":"opt3","if":"vlan30"}],"total":1}`, true},
		{`{"rows":[{"identifier":"opt3"}],"total":1}`, false},
		{`{"rows":[{"identifier":"lan","if":"igb0"},{"identifier":"lan","if":"igb1"}],"total":2}`, false},
		{`{"rows":[0],"total":1}`, false}, {`{"rows":[],"total":1}`, false},
	} {
		c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { testutil.WriteBody(w, tc.body) })
		if _, err := c.Assignments(t.Context()); (err == nil) != tc.valid {
			t.Fatalf("grid %s: %v", tc.body, err)
		}
	}
}

func TestAssignmentWritesAndPartialReplies(t *testing.T) {
	for _, addr := range []string{"192.0.2.1/24", "2001:db8::1/64"} {
		for _, reply := range []string{`{"result":"saved","uuid":"opt3"}`, `{"result":"failed"}`, `{`} {
			calls := 0
			c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != "POST" || !strings.HasSuffix(r.URL.Path, "/add_item") {
					t.Error("unexpected request")
				}
				testutil.WriteBody(w, reply)
			})
			id, err := c.StageAssignment(t.Context(), "vlan30", "gaming", netip.MustParsePrefix(addr))
			want := strings.Contains(reply, "saved")
			if (err == nil) != want || want && id != "opt3" || calls != 1 {
				t.Fatalf("add %v %v calls=%d", id, err, calls)
			}
		}
	}
	for _, status := range []string{"ok", "pending", "unrecognized"} {
		c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { testutil.WriteBody(w, `{"status":"`+status+`"}`) })
		pending, err := c.AssignmentsPending(t.Context())
		if pending != (status == "pending") || (err != nil) != (status == "unrecognized") {
			t.Fatalf("queue %s %v", status, err)
		}
		if err := c.ActivateAssignments(t.Context()); (err == nil) != (status == "ok") {
			t.Fatalf("reconfigure %s %v", status, err)
		}
	}
}

func TestAssignmentRequiresCompleteVLANInventory(t *testing.T) {
	for _, body := range []string{`{"total":1,"rows":[]}`, `{"total":1,"rows":[{"if":"igb0"}]}`, `{"total":1,"rows":[{"uuid":"v1","if":"igb0","tag":"wrong"}]}`} {
		c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { testutil.WriteBody(w, body) })
		if _, err := c.AssignmentVLANs(t.Context()); err == nil {
			t.Fatal("accepted incomplete VLAN target inventory")
		}
	}
}
