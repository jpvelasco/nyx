package opnsense

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
)

func TestFilterAliasWritesAndHelpers(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "add_") {
			testutil.WriteBody(w, `{"result":"saved","uuid":"new"}`)
			return
		}
		testutil.WriteBody(w, `{"result":"saved"}`)
	}))
	id, err := c.CreateFilterRule(context.Background(), FilterWrite{Action: "block", Source: "lan", Destination: "iot", Enabled: true, Description: "isolate"})
	if err != nil || id != "new" {
		t.Fatalf("create filter = %q %v", id, err)
	}
	if err := c.SetFilterRule(context.Background(), "r1", FilterWrite{Action: "pass", Source: "lan", Destination: "any"}); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteFilterRule(context.Background(), "r1"); err != nil {
		t.Fatal(err)
	}
	id, err = c.CreateAlias(context.Background(), AliasWrite{Name: "iot_net", Type: "network", Addresses: []string{"10.0.60.0/24"}, Enabled: true})
	if err != nil || id != "new" {
		t.Fatalf("create alias = %q %v", id, err)
	}
	if err := c.SetAlias(context.Background(), "a1", AliasWrite{Name: "iot_net", Addresses: []string{"10.0.60.0/24"}}); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteAlias(context.Background(), "a1"); err != nil {
		t.Fatal(err)
	}
	if err := c.ReconfigureAliases(context.Background()); err != nil {
		t.Fatal(err)
	}

	rules := []FirewallRule{{RuleUUID: "r1", Action: "block", Source: "lan", Destination: "iot", Label: "isolate"}}
	if got, ok := FindFilterRule(rules, "r1", ""); !ok || got.Label != "isolate" {
		t.Fatal("uuid match")
	}
	if got, ok := FindFilterRule(rules, "", "isolate"); !ok || got.RuleUUID != "r1" {
		t.Fatal("label match")
	}
	if !FilterMatchesWrite(rules[0], FilterWrite{Action: "block", Source: "lan", Destination: "iot", Description: "isolate", Enabled: true}) {
		t.Fatal("want match")
	}
	if FilterMatchesWrite(rules[0], FilterWrite{Action: "pass", Source: "lan", Destination: "iot"}) {
		t.Fatal("want action mismatch")
	}
	aliases := []Alias{{UUID: "a1", Name: "iot_net", Type: "network", Addresses: []string{"10.0.60.0/24"}}}
	if got, ok := FindAlias(aliases, "", "iot_net"); !ok || got.UUID != "a1" {
		t.Fatal("alias name match")
	}
	if !AliasMatchesWrite(aliases[0], AliasWrite{Name: "iot_net", Type: "network", Addresses: []string{"10.0.60.0/24"}}) {
		t.Fatal("want alias match")
	}
	if _, ok := FindFilterRule(rules, "", "missing"); ok {
		t.Fatal("want filter miss")
	}
	if _, ok := FindAlias(aliases, "a1", ""); !ok {
		t.Fatal("want alias uuid match")
	}
	if _, ok := FindAlias(aliases, "", "missing"); ok {
		t.Fatal("want alias miss")
	}
	if FilterMatchesWrite(rules[0], FilterWrite{Action: "block", Source: "guest", Destination: "iot", Enabled: true}) {
		t.Fatal("want source mismatch")
	}
	if FilterMatchesWrite(rules[0], FilterWrite{Action: "block", Source: "lan", Destination: "guest", Enabled: true}) {
		t.Fatal("want dest mismatch")
	}
	if AliasMatchesWrite(aliases[0], AliasWrite{Name: "other"}) {
		t.Fatal("want alias name mismatch")
	}
	if FilterMatchesWrite(rules[0], FilterWrite{Action: "block", Source: "lan", Destination: "iot", Description: "other", Enabled: true}) {
		t.Fatal("want description mismatch")
	}
	if AliasMatchesWrite(aliases[0], AliasWrite{Name: "iot_net", Type: "host", Addresses: []string{"10.0.60.0/24"}}) {
		t.Fatal("want alias type mismatch")
	}
	w := FilterWrite{Action: "block", Interface: "lan", Protocol: "tcp", SourcePort: "any", DestPort: "443", Direction: "in", IPProtocol: "inet", Description: "https"}
	if _, err := filterWire(w); err != nil {
		t.Fatal(err)
	}
	if _, err := aliasWire(AliasWrite{Name: "x", Description: "y"}); err != nil {
		t.Fatal(err)
	}
}
