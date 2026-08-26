package opnsense

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
)

// S2.4 — single firewall rule by UUID.
func TestGetFirewallRule(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/firewall/filter/get_rule/u-123" {
				t.Errorf("path = %q, want /api/firewall/filter/get_rule/u-123", r.URL.Path)
			}
			testutil.WriteBody(w, `{"uuid":"u-123","enabled":"0","action":"block","description":"deny lan to iot","interface":["lan"],"source_net":"10.0.0.5","destination_net":"203.0.113.9"}`)
		}))
		rule, err := c.GetFirewallRule(context.Background(), "u-123")
		if err != nil {
			t.Fatalf("GetFirewallRule: %v", err)
		}
		if rule.RuleUUID != "u-123" || !rule.Disabled || rule.Source != "10.0.0.5" {
			t.Errorf("rule = %+v", rule)
		}
	})

	t.Run("errors propagate", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		_, err := c.GetFirewallRule(context.Background(), "missing")
		if err == nil || !strings.Contains(err.Error(), "resource not found") {
			t.Errorf("error = %v, want resource not found", err)
		}
	})
}

// S2.6 — port forward (destination NAT) rules.
func TestGetPortForwardRules(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/firewall/d_nat/search_rule" {
				t.Errorf("path = %q, want /api/firewall/d_nat/search_rule", r.URL.Path)
			}
			testutil.WriteBody(w, `{"total":2,"rows":[
				{"rule":[{"uuid":"n1","interface":["wan"],"protocol":"tcp","source":{"network":"any"},"destination":{"network":"203.0.113.1","port":"443"},"local-port":"443","disabled":false,"descr":"web-iot"}]},
				{"rule":[{"uuid":"n2","interface":["wan"],"protocol":"udp","source":{"network":"10.0.0.0/24","address":null},"destination":{"network":"203.0.113.1","port":"53"},"local-port":"53","disabled":true,"descr":"dns-lan"}]}
			]}`)
		}))
		rules, err := c.GetPortForwardRules(context.Background())
		if err != nil {
			t.Fatalf("GetPortForwardRules: %v", err)
		}
		if len(rules) != 2 {
			t.Fatalf("rules = %+v, want 2", rules)
		}
		r0 := rules[0]
		if r0.RuleUUID != "n1" || r0.Source != "any" || r0.Destination != "203.0.113.1" || r0.Port != "443" || r0.Label != "web-iot" || r0.Disabled || r0.Protocol != "TCP" {
			t.Errorf("rule[0] = %+v", r0)
		}
		if len(r0.Interface) != 1 || r0.Interface[0] != "wan" {
			t.Errorf("rule[0] interfaces = %v, want [wan]", r0.Interface)
		}
		r1 := rules[1]
		if !r1.Disabled || r1.Source != "10.0.0.0/24" || r1.Protocol != "UDP" {
			t.Errorf("rule[1] = %+v", r1)
		}
	})

	t.Run("rows without rule array are skipped", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `{"total":1,"rows":[
				{},
				{"rule":[{"uuid":"n1","interface":["wan"],"descr":"only-one"}]}
			]}`)
		}))
		rules, err := c.GetPortForwardRules(context.Background())
		if err != nil {
			t.Fatalf("GetPortForwardRules: %v", err)
		}
		if len(rules) != 1 || rules[0].RuleUUID != "n1" {
			t.Errorf("rules = %+v, want the single well-formed rule", rules)
		}
	})

	t.Run("bad json", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `not json`)
		}))
		_, err := c.GetPortForwardRules(context.Background())
		if err == nil || !strings.Contains(err.Error(), "decoding port forward rules response") {
			t.Errorf("error = %v, want decoding port forward rules response", err)
		}
	})
}

// S2.7 — one-to-one NAT rules.
func TestGetOneToOneRules(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/firewall/one_to_one/search_rule" {
				t.Errorf("path = %q, want /api/firewall/one_to_one/search_rule", r.URL.Path)
			}
			testutil.WriteBody(w, `{"total":1,"rows":[
				{"rule":[{"uuid":"o1","interface":["wan"],"type":"binat","source":{"network":"10.0.0.10"},"destination":{"network":"203.0.113.10"},"disabled":false,"descr":"nas passthrough"}]}
			]}`)
		}))
		rules, err := c.GetOneToOneRules(context.Background())
		if err != nil {
			t.Fatalf("GetOneToOneRules: %v", err)
		}
		if len(rules) != 1 {
			t.Fatalf("rules = %+v, want 1", rules)
		}
		r := rules[0]
		if r.RuleUUID != "o1" || r.Source != "10.0.0.10" || r.Destination != "203.0.113.10" || r.Label != "nas passthrough" || r.Type != "binat" || r.Disabled {
			t.Errorf("rule = %+v", r)
		}
	})

	t.Run("bad json", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `not json`)
		}))
		_, err := c.GetOneToOneRules(context.Background())
		if err == nil || !strings.Contains(err.Error(), "decoding one-to-one rules response") {
			t.Errorf("error = %v, want decoding one-to-one rules response", err)
		}
	})
}

// S2.8 — source NAT rules (incl. the generic outbound-NAT row).
func TestGetSourceNatRules(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/firewall/source_nat/search_rule" {
				t.Errorf("path = %q, want /api/firewall/source_nat/search_rule", r.URL.Path)
			}
			testutil.WriteBody(w, `{"total":2,"rows":[
				{"rule":[{"uuid":"s1","interface":["lan"],"source":{"network":"10.0.0.0/24"},"destination":{"network":"any"},"target":"203.0.113.100","disabled":false,"descr":"force snat"}]},
				{"rule":[{"uuid":"s2","interface":["lan"],"snat_mode":"automatic","source":{"network":"10.0.0.0/24"},"destination":{"network":"any"},"disabled":false,"descr":"Outbound NAT"}]}
			]}`)
		}))
		rules, err := c.GetSourceNatRules(context.Background())
		if err != nil {
			t.Fatalf("GetSourceNatRules: %v", err)
		}
		if len(rules) != 2 {
			t.Fatalf("rules = %+v, want 2", rules)
		}
		if rules[0].Target != "203.0.113.100" || rules[0].Label != "force snat" {
			t.Errorf("rule[0] = %+v", rules[0])
		}
		if rules[1].SNATMode != "automatic" {
			t.Errorf("rule[1] = %+v, want the generic outbound-NAT row preserved with snat_mode", rules[1])
		}
	})

	t.Run("bad json", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `not json`)
		}))
		_, err := c.GetSourceNatRules(context.Background())
		if err == nil || !strings.Contains(err.Error(), "decoding source NAT rules response") {
			t.Errorf("error = %v, want decoding source NAT rules response", err)
		}
	})
}

// S2.9 — outbound NAT mode from the general firewall config.
func TestGetOutboundNatMode(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/firewall/filter_base/get" {
				t.Errorf("path = %q, want /api/firewall/filter_base/get", r.URL.Path)
			}
			testutil.WriteBody(w, `{"general":{"snat_mode":"disabled"}}`)
		}))
		mode, err := c.GetOutboundNatMode(context.Background())
		if err != nil {
			t.Fatalf("GetOutboundNatMode: %v", err)
		}
		if mode != "disabled" {
			t.Errorf("mode = %q, want disabled", mode)
		}
	})

	t.Run("other modes decode", func(t *testing.T) {
		for _, want := range []string{"automatic", "hybrid", "advanced", "disabled"} {
			c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				testutil.WriteBody(w, `{"general":{"snat_mode":"`+want+`"}}`)
			}))
			mode, err := c.GetOutboundNatMode(context.Background())
			if err != nil {
				t.Fatalf("GetOutboundNatMode(%s): %v", want, err)
			}
			if mode != want {
				t.Errorf("mode = %q, want %q", mode, want)
			}
		}
	})

	t.Run("bad json", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `not json`)
		}))
		_, err := c.GetOutboundNatMode(context.Background())
		if err == nil || !strings.Contains(err.Error(), "decoding firewall base response") {
			t.Errorf("error = %v, want decoding firewall base response", err)
		}
	})
}

// S2.10 — aliases.
func TestGetAliases(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/firewall/alias/search_item" {
				t.Errorf("path = %q, want /api/firewall/alias/search_item", r.URL.Path)
			}
			testutil.WriteBody(w, `{"total":2,"rows":[
				{"uuid":"a1","name":"WEB","type":"host","address":"10.0.40.10","description":"web server","details":["10.0.40.10"],"enabled":"1"},
				{"uuid":"a2","name":"LAN-SERVERS","type":"net","address":"10.0.40.0/24","description":"server VLAN","details":["10.0.40.0/24"],"enabled":"1"}
			]}`)
		}))
		aliases, err := c.GetAliases(context.Background())
		if err != nil {
			t.Fatalf("GetAliases: %v", err)
		}
		if len(aliases) != 2 {
			t.Fatalf("aliases = %+v, want 2", aliases)
		}
		a0 := aliases[0]
		if a0.UUID != "a1" || a0.Name != "WEB" || a0.Type != "host" || a0.Description != "web server" || a0.Disabled {
			t.Errorf("alias[0] = %+v", a0)
		}
		if len(a0.Addresses) != 1 || a0.Addresses[0] != "10.0.40.10" {
			t.Errorf("alias[0] addresses = %v, want [10.0.40.10]", a0.Addresses)
		}
		if aliases[1].Type != "net" || aliases[1].Addresses[0] != "10.0.40.0/24" {
			t.Errorf("alias[1] = %+v", aliases[1])
		}
	})

	t.Run("bad json", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `not json`)
		}))
		_, err := c.GetAliases(context.Background())
		if err == nil || !strings.Contains(err.Error(), "decoding aliases response") {
			t.Errorf("error = %v, want decoding aliases response", err)
		}
	})

	t.Run("404 endpoint", func(t *testing.T) {
		// A 404 is a stable error (no retries), so the read fails fast.
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			testutil.WriteBody(w, `{"message":"missing"}`)
		}))
		_, err := c.GetAliases(context.Background())
		if err == nil || !strings.Contains(err.Error(), "resource not found") {
			t.Errorf("error = %v, want resource-not-found", err)
		}
	})
}

// decodeNatRow edge cases: malformed rule elements are skipped (nil), the
// address field backs up a missing network, and the "1"/"0" enabled string
// wins over the bool flag when both are present.
func TestDecodeNatRow_Edges(t *testing.T) {
	t.Run("malformed rule element is skipped", func(t *testing.T) {
		if r := decodeNatRow(json.RawMessage(`{"rule":["not-an-object"]}`)); r != nil {
			t.Errorf("decodeNatRow = %+v, want nil", r)
		}
		if r := decodeNatRow(json.RawMessage(`{"rule":42}`)); r != nil {
			t.Errorf("decodeNatRow = %+v, want nil", r)
		}
	})

	t.Run("address backs up a missing network", func(t *testing.T) {
		r := decodeNatRow(json.RawMessage(`{"rule":[{"uuid":"x","source":{"network":"","address":"10.0.40.99"},"destination":{"network":"","address":"203.0.113.9"}}]}`))
		if r == nil {
			t.Fatal("decodeNatRow = nil, want the rule with address fallback")
		}
		if r.Source != "10.0.40.99" || r.Destination != "203.0.113.9" {
			t.Errorf("source=%q destination=%q, want the address fallback", r.Source, r.Destination)
		}
	})

	t.Run("enabled string wins over the disabled bool", func(t *testing.T) {
		r := decodeNatRow(json.RawMessage(`{"rule":[{"uuid":"x","disabled":false,"enabled":"0"}]}`))
		if r == nil || !r.Disabled {
			t.Errorf("decodeNatRow = %+v, want disabled (enabled=\"0\")", r)
		}
		r = decodeNatRow(json.RawMessage(`{"rule":[{"uuid":"x","disabled":true,"enabled":"1"}]}`))
		if r == nil || r.Disabled {
			t.Errorf("decodeNatRow = %+v, want enabled (enabled=\"1\")", r)
		}
	})
}

// rawRows: empty input and non-array input both yield no rows.
func TestRawRows(t *testing.T) {
	if got := rawRows(nil); got != nil {
		t.Errorf("rawRows(nil) = %v, want nil", got)
	}
	if got := rawRows(json.RawMessage(`{"rows":"not-an-array"}`)); got != nil {
		t.Errorf("rawRows(non-array) = %v, want nil", got)
	}
	if got := rawRows(json.RawMessage(`[{"a":1},{"b":2}]`)); len(got) != 2 {
		t.Errorf("rawRows(array) = %v, want 2 rows", got)
	}
}

// natRules propagates transport-level failures (404) without wrapping.
func TestNatRules_RequestFailure(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	_, err := c.GetPortForwardRules(context.Background())
	if err == nil || !strings.Contains(err.Error(), "resource not found") {
		t.Errorf("error = %v, want resource not found", err)
	}
}

// S2.5 — GetFirewallRule decode failure.
func TestGetFirewallRule_BadJSON(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		testutil.WriteBody(w, `not json`)
	}))
	_, err := c.GetFirewallRule(context.Background(), "u-123")
	if err == nil || !strings.Contains(err.Error(), "decoding firewall rule response") {
		t.Errorf("error = %v, want decoding firewall rule response", err)
	}
}

// S2.10 — GetAliases: a malformed row is skipped, and a row without
// details falls back to the comma-separated address field.
func TestGetAliases_Rows(t *testing.T) {
	t.Run("malformed row is skipped", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `{"total":2,"rows":[123,{"uuid":"a1","name":"WEB","type":"host","details":["10.0.40.10"],"enabled":"1"}]}`)
		}))
		aliases, err := c.GetAliases(context.Background())
		if err != nil {
			t.Fatalf("GetAliases: %v", err)
		}
		if len(aliases) != 1 || aliases[0].Name != "WEB" {
			t.Errorf("aliases = %+v, want the single well-formed alias", aliases)
		}
	})

	t.Run("address field splits on commas without details", func(t *testing.T) {
		c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			testutil.WriteBody(w, `{"total":1,"rows":[{"uuid":"a2","name":"PAIR","type":"host","address":"10.0.40.10,10.0.40.11","enabled":"1"}]}`)
		}))
		aliases, err := c.GetAliases(context.Background())
		if err != nil {
			t.Fatalf("GetAliases: %v", err)
		}
		if len(aliases) != 1 || len(aliases[0].Addresses) != 2 ||
			aliases[0].Addresses[0] != "10.0.40.10" || aliases[0].Addresses[1] != "10.0.40.11" {
			t.Errorf("aliases = %+v, want two addresses from the comma split", aliases)
		}
	})
}

// Reads never mutate: no POST leaves the client for any read surface.
func TestReadsIssueNoMutations(t *testing.T) {
	var sawPost bool
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			sawPost = true
		}
		switch r.URL.Path {
		case "/api/firewall/filter/get_rule/u":
			testutil.WriteBody(w, `{"uuid":"u","enabled":"1"}`)
		case "/api/firewall/d_nat/search_rule":
			testutil.WriteBody(w, `{"total":0,"rows":[]}`)
		case "/api/firewall/one_to_one/search_rule":
			testutil.WriteBody(w, `{"total":0,"rows":[]}`)
		case "/api/firewall/source_nat/search_rule":
			testutil.WriteBody(w, `{"total":0,"rows":[]}`)
		case "/api/firewall/filter_base/get":
			testutil.WriteBody(w, `{"general":{"snat_mode":"disabled"}}`)
		case "/api/firewall/alias/search_item":
			testutil.WriteBody(w, `{"total":0,"rows":[]}`)
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	ctx := context.Background()
	if _, err := c.GetFirewallRule(ctx, "u"); err != nil {
		t.Fatalf("GetFirewallRule: %v", err)
	}
	if _, err := c.GetPortForwardRules(ctx); err != nil {
		t.Fatalf("GetPortForwardRules: %v", err)
	}
	if _, err := c.GetOneToOneRules(ctx); err != nil {
		t.Fatalf("GetOneToOneRules: %v", err)
	}
	if _, err := c.GetSourceNatRules(ctx); err != nil {
		t.Fatalf("GetSourceNatRules: %v", err)
	}
	if _, err := c.GetOutboundNatMode(ctx); err != nil {
		t.Fatalf("GetOutboundNatMode: %v", err)
	}
	if _, err := c.GetAliases(ctx); err != nil {
		t.Fatalf("GetAliases: %v", err)
	}
	if sawPost {
		t.Error("a read issued a non-GET request — reads must never mutate")
	}
}
