package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/audit"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/probe/fake"
	"github.com/jpvelasco/nyx/internal/testutil"
	"gopkg.in/yaml.v3"
)

func gamingSegment() SegmentRequest {
	first := netip.MustParseAddr("10.0.30.1").Next()
	return SegmentRequest{Role: "gaming", Tag: 30, Parent: "igb0", Gateway: "10.0.30.1/24", Management: "10.0.11.0/24", Resolver: "10.0.40.1", Start: first.String(), End: first.Next().String()}
}

// These servers persist the exact payloads across requests, including the separate
// assignment activation. Unexpected writes fail instead of returning generic success.
type segmentFixture struct {
	t                       *testing.T
	req                     SegmentRequest
	vlan, assignment, rules []map[string]string
	ranges                  map[string]map[string]string
	lans                    []map[string]any
	writes                  int
	pending                 string
	lease                   bool
}

func (f *segmentFixture) row(r *http.Request, key string) map[string]string {
	f.t.Helper()
	var body map[string]map[string]string
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body[key] == nil {
		f.t.Errorf("%s payload %v", key, err)
		return map[string]string{}
	}
	f.writes++
	return body[key]
}
func (f *segmentFixture) firewall(w http.ResponseWriter, r *http.Request) {
	enc := json.NewEncoder(w)
	grid := func(rows []map[string]string) {
		if rows == nil {
			rows = []map[string]string{}
		}
		_ = enc.Encode(map[string]any{"rows": rows, "total": len(rows)})
	}
	saved := func(id string) { _ = enc.Encode(map[string]string{"result": "saved", "uuid": id}) }
	switch r.URL.Path {
	case "/api/interfaces/overview/interfaces_info":
		testutil.WriteBody(w, `{"interfaces":{"lan":{"description":"management","ipv4":"10.0.11.1/24"}}}`)
	case "/api/diagnostics/interface/get_routes":
		testutil.WriteBody(w, `[{"destination":"default","netif":"igb0"}]`)
	case "/api/interfaces/vlan_settings/search_item":
		grid(f.vlan)
	case "/api/interfaces/vlan_settings/add_item":
		row := f.row(r, "vlan")
		row["uuid"] = "v1"
		row["vlanif"] = "vlan30"
		f.vlan = append(f.vlan, row)
		saved("v1")
	case "/api/interfaces/assignment/search_item":
		grid(f.assignment)
	case "/api/interfaces/assignment/pending":
		_ = enc.Encode(map[string]string{"status": f.pending})
	case "/api/interfaces/assignment/add_item":
		row := f.row(r, "interface")
		row["identifier"] = "opt3"
		row["pending_action"] = "update"
		f.assignment = append(f.assignment, row)
		f.pending = "pending"
		saved("opt3")
	case "/api/interfaces/assignment/reconfigure":
		f.assignment[0]["pending_action"] = ""
		f.pending = "ok"
		f.writes++
		testutil.WriteBody(w, `{"status":"ok"}`)
	case "/api/firewall/filter/search_rule":
		grid(f.rules)
	case "/api/firewall/filter/add_rule":
		row := f.row(r, "rule")
		row["uuid"] = "rule-" + strconv.Itoa(len(f.rules))
		f.rules = append(f.rules, row)
		saved(row["uuid"])
	case "/api/dnsmasq/settings/get":
		_ = enc.Encode(map[string]any{"dnsmasq": map[string]any{"enable": "1", "dhcp_ranges": f.ranges}})
	case "/api/kea/service/status":
		testutil.WriteBody(w, `{"running":false}`)
	case "/api/dnsmasq/settings/add_range":
		row := f.row(r, "range")
		if len(row) != 3 || row["interface"] != "opt3" || row["start_addr"] != f.req.Start || row["end_addr"] != f.req.End {
			f.t.Error("wrong DHCP range fields")
		}
		f.ranges["range-1"] = row
		saved("range-1")
	case "/api/dnsmasq/leases/search":
		if f.lease {
			grid([]map[string]string{{"ip": f.req.Start}})
		} else {
			grid(nil)
		}
	case "/api/interfaces/vlan_settings/reconfigure", "/api/firewall/filter/apply", "/api/dnsmasq/service/reconfigure":
		f.writes++
		testutil.WriteBody(w, `{"status":"ok"}`)
	default:
		f.t.Errorf("unexpected firewall operation %s", r.URL.Path)
		http.NotFound(w, r)
	}
}
func (f *segmentFixture) controller(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/openapi/authorize/token":
		writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
	case strings.HasSuffix(r.URL.Path, "/sites"):
		writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"site"}]}`)
	case strings.HasSuffix(r.URL.Path, "/lan-networks") && r.Method == http.MethodGet:
		data, _ := json.Marshal(map[string]any{"totalRows": len(f.lans), "data": f.lans})
		writeOmadaEnvelope(w, 0, string(data))
	case strings.HasSuffix(r.URL.Path, "/lan-networks") && r.Method == http.MethodPost:
		var row map[string]any
		if err := json.NewDecoder(r.Body).Decode(&row); err != nil {
			f.t.Error(err)
		}
		row["id"] = "network-1"
		f.lans = append(f.lans, row)
		f.writes++
		writeOmadaEnvelope(w, 0, `{"id":"network-1"}`)
	default:
		f.t.Errorf("unexpected controller operation %s", r.URL.Path)
		http.NotFound(w, r)
	}
}
func newSegmentFixture(t *testing.T) (*segmentFixture, PlaybookOptions) {
	t.Helper()
	f := &segmentFixture{t: t, req: gamingSegment(), pending: "ok", ranges: map[string]map[string]string{}, lans: []map[string]any{}}
	firewall := opnsenseOptions(opnsenseTestServer(t, f.firewall))
	omada := OmadaOptions{Host: omadaTestServer(t, f.controller).URL, ClientID: "client", ClientSecret: "fixture", Site: "site", SkipTLSVerify: true}
	return f, PlaybookOptions{Omada: &omada, Opnsense: &firewall}
}
func TestSegmentProvisionAndResume(t *testing.T) {
	f, opts := newSegmentFixture(t)
	ctx := t.Context()
	svc := SegmentService{Topology: &stubTopoForPlaybook{rep: onPathNatRouter("opnsense")}}
	svc.audit = segmentProbeSpec(t, f.req)
	call := func(dry bool) []SegmentStep {
		t.Helper()
		report, err := svc.Reconcile(ctx, opts, f.req, dry)
		if err != nil {
			t.Fatal(err)
		}
		return report.Steps
	}
	steps := call(true)
	if steps[0].Status != "verified" || steps[1].Status != "create" || steps[2].Status != "waiting" || f.writes != 0 {
		t.Fatalf("initial preview %+v", steps)
	}
	steps = call(false)
	last := steps[len(steps)-1]
	if last.Status != "review" || !strings.Contains(last.Detail, "active lease") {
		t.Fatalf("missing lease should stop verification: %+v", steps)
	}
	if len(f.rules) != 2 || f.rules[0]["action"] != "block" || f.rules[0]["destination_net"] != f.req.Management || f.rules[1]["destination_net"] != f.req.Resolver || f.rules[1]["destination_port"] != "53" || f.rules[0]["interface"] != "opt3" || f.rules[1]["interface"] != "opt3" || len(f.assignment) != 1 || len(f.lans) != 1 || len(f.ranges) != 1 {
		t.Fatal("incorrect ownership or service selectors")
	}
	count := f.writes
	f.lease = true
	steps = call(false)
	for _, step := range steps {
		if step.Status != "unchanged" && step.Status != "verified" {
			t.Fatalf("resume %+v", steps)
		}
	}
	if steps[len(steps)-1].Status != "verified" || f.writes != count {
		t.Fatal("resume repeated a write or left measurements unverified")
	}
	f.rules = append(f.rules, map[string]string{"uuid": "floating", "action": "pass", "source_net": "any", "destination_net": "any", "enabled": "1"})
	steps = call(false)
	if steps[0].Status != "review" || f.writes != count {
		t.Fatal("ambiguous pass rule did not stop provisioning")
	}
}

func segmentProbeSpec(t *testing.T, r SegmentRequest) segmentAudit {
	t.Helper()
	const answer = "192.0.2.8"
	source := intent.Probe{Name: "source", User: "test", Host: r.Start, VLAN: r.Role}
	mgmt := intent.Probe{Name: "admin-control", User: "test", Host: "10.0.11.1", VLAN: "management"}
	resolver := intent.Probe{Name: "dns-control", User: "test", Host: r.Resolver, VLAN: "servers"}
	dns := intent.Assertion{Name: "resolver", Type: "dns_check", Runner: source.Name, Server: r.Resolver, Query: "service.example", ExpectIP: answer}
	deny := intent.Assertion{Name: "isolation", Type: "port_check", Runner: source.Name, Target: mgmt.Host, Ports: []int{443}, Expect: "closed"}
	positiveDNS, positiveTCP := dns, deny
	positiveDNS.Name = "positive-dns"
	positiveDNS.Runner = resolver.Name
	positiveTCP.Name = "positive-tcp"
	positiveTCP.Runner = mgmt.Name
	positiveTCP.Expect = "open"
	spec := intent.Spec{Version: 1, Site: "trusted", Networks: []intent.Network{{Name: r.Role, VLAN: r.Tag, CIDR: "10.0.30.0/24"}, {Name: "management", CIDR: r.Management}, {Name: "servers", CIDR: "10.0.40.0/24"}}, Probes: []intent.Probe{source, mgmt, resolver}, Policies: []intent.Policy{{Name: "permitted-dns", From: r.Role, To: "servers", Action: "allow"}, {Name: "management-isolation", From: r.Role, To: "management", Action: "deny"}}, Assertions: []intent.Assertion{dns, positiveDNS, deny, positiveTCP, {Name: "unrelated", Type: "network_health", Target: r.Resolver}}, ServicePolicies: []intent.ServicePolicy{{Policy: "permitted-dns", Measurement: dns.Name, PositiveControl: positiveDNS.Name}, {Policy: "management-isolation", Measurement: deny.Name, PositiveControl: positiveTCP.Name}}}
	path := filepath.Join(t.TempDir(), "spec.yaml")
	data, err := yaml.Marshal(&spec)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NYX_SEGMENT_VERIFICATION_SPEC", path)
	key := filepath.Join(t.TempDir(), "fixture-key")
	fake.WriteKey(t, key)
	ports := map[string]int{}
	for _, p := range spec.Probes {
		srv := fake.Start(t, fake.Options{ExecReply: true, OnExec: func(cmd string) (string, uint32) {
			switch {
			case strings.Contains(cmd, "nslookup") && p.Name != mgmt.Name:
				return "Name: service.example\nAddress: " + answer + "\n", 0
			case strings.Contains(cmd, "nc") && p.Name == mgmt.Name:
				return "", 0
			case strings.Contains(cmd, "nc") && p.Name == source.Name:
				return "", 1
			}
			t.Errorf("unexpected command for %s", p.Name)
			return "", 2
		}})
		ports[p.Name] = srv.Port
	}
	return func(ctx context.Context, selected *intent.Spec) (*models.AuditReport, error) {
		if len(selected.Assertions) != 4 || len(selected.ServicePolicies) != 2 {
			return nil, errors.New("incorrectly selected verification checks")
		}
		for i, p := range selected.Probes {
			selected.Probes[i].Host = "127.0.0.1"
			selected.Probes[i].Port = ports[p.Name]
			selected.Probes[i].Key = key
			selected.Probes[i].SkipHostKeyVerify = true
		}
		return audit.NewEngine(selected).Run(ctx)
	}
}

func TestSegmentConstraints(t *testing.T) {
	for _, bad := range []func(*SegmentRequest){func(r *SegmentRequest) { r.Role = "management" }, func(r *SegmentRequest) { r.Tag = 4095 }, func(r *SegmentRequest) { r.Gateway = r.Management }, func(r *SegmentRequest) { r.Gateway = "10.0.30.1/3" }, func(r *SegmentRequest) { r.Management = "10.0.11.1/24" }, func(r *SegmentRequest) { r.Resolver = "10.0.11.1" }, func(r *SegmentRequest) { r.Start = "10.0.30.1" }, func(r *SegmentRequest) { r.End, r.Start = r.Start, r.End }, func(r *SegmentRequest) { r.Resolver = r.Start }} {
		r := gamingSegment()
		bad(&r)
		if r.Validate() == nil {
			t.Fatalf("accepted invalid segment %+v", r)
		}
	}
	r := gamingSegment()
	_, opts := newSegmentFixture(t)
	svc := SegmentService{Topology: &stubTopoForPlaybook{rep: onPathNatRouter("omada")}}
	if _, err := svc.Reconcile(t.Context(), opts, r, false); err == nil {
		t.Fatal("accepted wrong routing owner")
	}
	opts.Omada.Site = ""
	if _, err := svc.Reconcile(t.Context(), opts, r, true); err == nil {
		t.Fatal("accepted implicit site")
	}
}
func TestSegmentUncertainWrites(t *testing.T) {
	for _, mode := range []string{"write error", "readback error", "mismatch"} {
		calls, writes := 0, 0
		op := segmentOperation{SegmentStep: SegmentStep{Name: "selected"}, run: func(dry bool) (string, error) {
			calls++
			switch {
			case !dry:
				writes++
				if mode == "write error" {
					return "", errors.New("interrupted")
				}
				return "created", nil
			case calls == 1:
				return "create", nil
			case mode == "readback error":
				return "", errors.New("unavailable")
			case mode == "mismatch":
				return "create", nil
			default:
				return "unchanged", nil
			}
		}}
		report := SegmentReport{}
		runSegment(&report, []segmentOperation{op, {SegmentStep: SegmentStep{Name: "dependent", DependsOn: []string{"selected"}}}})
		if calls != 3 || writes != 1 || report.Steps[1].Status != "waiting" || report.Attention() == nil {
			t.Fatalf("%s %+v", mode, report)
		}
	}
}
func TestSegmentVerificationGuards(t *testing.T) {
	r := gamingSegment()
	_ = segmentProbeSpec(t, r)
	load := func() *intent.Spec {
		s, err := intent.LoadSpec(os.Getenv("NYX_SEGMENT_VERIFICATION_SPEC"))
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	for _, alter := range []func(*intent.Spec){func(s *intent.Spec) { s.Networks[0].VLAN++ }, func(s *intent.Spec) { s.ServicePolicies = s.ServicePolicies[:1] }, func(s *intent.Spec) { s.Probes[0].Host = "probe.example" }, func(s *intent.Spec) { s.ServicePolicies[0].Measurement = "missing" }} {
		s := load()
		alter(s)
		if _, _, err := segmentVerificationSpec(s, r); err == nil {
			t.Fatal("accepted unverified source or service")
		}
	}
	spec := load()
	for _, report := range []*models.AuditReport{{}, {Findings: []models.CheckResult{{CheckType: "service_policy", Status: models.StatusFail}}}} {
		if _, err := verifySegmentServices(t.Context(), spec, func(context.Context, *intent.Spec) (*models.AuditReport, error) { return report, nil }); err == nil {
			t.Fatal("accepted partial or failed measurements")
		}
	}
}

func TestSegmentControllerCollisionsAndManualWireless(t *testing.T) {
	f, opts := newSegmentFixture(t)
	e := segmentProviders{ctx: t.Context(), omada: *opts.Omada, firewall: *opts.Opnsense, req: f.req, router: NewOpnsenseService(), switchAPI: NewOmadaService(), iface: "opt3"}
	f.lans = []map[string]any{{"id": "network-1", "name": "protected", "vlan": f.req.Tag, "purpose": 0}}
	if _, err := e.preflight(true); err == nil || f.writes != 0 {
		t.Fatal("controller tag collision was accepted")
	}
	f.ranges["other"] = map[string]string{"interface": "lan", "start_addr": f.req.Start, "end_addr": f.req.End}
	if _, err := e.dhcp(false); err == nil || f.writes != 0 {
		t.Fatal("overlapping pool was accepted")
	}
	t.Setenv("NYX_SEGMENT_VERIFICATION_SPEC", "")
	if status, err := e.verify(true); err != nil || status != "manual" {
		t.Fatal("missing verification spec was accepted")
	}
	e.req.SSID = "gaming"
	for _, tc := range []struct {
		security string
		tag      int
		enabled  bool
		want     string
	}{{"wpa3", 30, true, "verified"}, {"open", 30, true, "manual"}, {"wpa3", 40, true, "manual"}, {"wpa3", 30, false, "manual"}} {
		server := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasSuffix(r.URL.Path, "/ssids"):
				data, _ := json.Marshal(map[string]any{"totalRows": 1, "data": []map[string]any{{"id": "ssid-1", "ssid": "gaming", "name": "gaming", "enable": tc.enabled, "security": tc.security, "vlanId": tc.tag}}})
				writeOmadaEnvelope(w, 0, string(data))
			case strings.HasSuffix(r.URL.Path, "/wlan-groups"):
				writeOmadaEnvelope(w, 0, `{"totalRows":0,"data":[]}`)
			default:
				f.controller(w, r)
			}
		})
		e.omada.Host = server.URL
		status, err := e.wireless(true)
		if err != nil || status != tc.want {
			t.Fatalf("wireless %s %d %v: %s %v", tc.security, tc.tag, tc.enabled, status, err)
		}
	}
	deps := e.operations()
	if deps[len(deps)-1].DependsOn[len(deps[len(deps)-1].DependsOn)-1] != "wireless" {
		t.Fatal("verification must wait for the specified SSID")
	}
}
