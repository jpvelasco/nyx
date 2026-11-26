package snapshot

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jpvelasco/nyx/internal/filewrite"
	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/topology"
)

// NetworkMapCapture is private local drift evidence. The network map uses
// native resource IDs so changes in report-local numbering cannot create drift.
type NetworkMapCapture struct {
	Version  int                          `json:"version"`
	At       time.Time                    `json:"at"`
	Map      topology.NetworkMap          `json:"map"`
	Policies map[string]PolicyObservation `json:"policies,omitempty"`
}
type PolicyObservation struct {
	Declared   string        `json:"declared"`
	Status     models.Status `json:"status"`
	Firewall   string        `json:"firewall_evidence"`
	RecordedAt time.Time     `json:"recorded_at"`
}
type MapChange struct {
	Reference string `json:"reference"`
	Subject   string `json:"subject"`
	Change    string `json:"change"`
	Impact    string `json:"impact"`
	Evidence  string `json:"evidence"`
	Previous  string `json:"previous,omitempty"`
	Current   string `json:"current,omitempty"`
}
type NetworkDrift struct {
	Before  time.Time   `json:"before"`
	After   time.Time   `json:"after"`
	Changes []MapChange `json:"changes"`
}

var mapCaptureName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

func mapCapturePath(name string) (string, error) {
	if !mapCaptureName.MatchString(name) {
		return "", errors.New("snapshot name must use 1 to 64 letters, numbers, hyphens or underscores")
	}
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "network-maps", name+".json"), nil
}
func SaveNetworkMapCapture(name string, c NetworkMapCapture, replace bool) error {
	path, err := mapCapturePath(name)
	if err != nil {
		return err
	}
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return errors.New("unable to create the private map snapshot directory")
	}
	if replace {
		return filewrite.Write(path, bytes.NewReader(data))
	}
	if err := filewrite.Create(path, bytes.NewReader(data)); err != nil {
		return errors.New("unable to create the named map snapshot; an existing name requires explicit replacement")
	}
	return nil
}
func LoadNetworkMapCapture(name string) (NetworkMapCapture, error) {
	path, err := mapCapturePath(name)
	if err != nil {
		return NetworkMapCapture{}, err
	}
	data, err := readSnapshotFile(filepath.Dir(path), filepath.Base(path))
	if err != nil {
		return NetworkMapCapture{}, errors.New("unable to read the selected network map snapshot")
	}
	var c NetworkMapCapture
	if err := json.Unmarshal(data, &c); err != nil || c.Version != 1 || c.At.IsZero() {
		return NetworkMapCapture{}, errors.New("invalid network map snapshot")
	}
	return c, nil
}

// AddServicePolicies captures the effective declared outcome for one assertion.
// The stable key is operator-assigned. Enforcement failures do not rewrite intent.
func (c *NetworkMapCapture) AddServicePolicies(audit *Snapshot) {
	c.Policies = map[string]PolicyObservation{}
	for _, f := range audit.Findings {
		if f.CheckType != "service_policy" {
			continue
		}
		name, ok := f.Expected["policy"].(string)
		outcome, _ := f.Expected["outcome"].(string)
		if !ok || name == "" || f.Target == "" {
			continue
		}
		firewall, _ := f.Observed["firewall_evidence"].(string)
		if firewall != "recorded" {
			firewall = "unavailable"
		}
		binding, _ := json.Marshal([]any{f.Observed["from"], f.Observed["to"], f.Observed["source_probe"], f.Observed["destination"], f.Observed["protocol"], f.Observed["port"], f.Observed["ip_family"]})
		c.Policies[stableMapRef("policy", name, f.Target, string(binding))] = PolicyObservation{Declared: outcome, Status: f.Status, Firewall: firewall, RecordedAt: audit.RunAt}
	}
}

func stableMapRef(parts ...string) string {
	data, _ := json.Marshal(parts)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:16])
}

// ReadNamedAudit restricts policy evidence to Nyx's private snapshot store.
func ReadNamedAudit(name string) (*Snapshot, error) {
	if name != "baseline.json" && !snapshotNameRe.MatchString(name) {
		return nil, errors.New("select an audit snapshot basename or baseline.json")
	}
	dir, err := Dir()
	if err != nil {
		return nil, err
	}
	data, err := readSnapshotFile(dir, name)
	if err != nil {
		return nil, errors.New("unable to read the named audit snapshot")
	}
	var snap Snapshot
	if err := json.Unmarshal(data, &snap); err != nil || snap.RunAt.IsZero() {
		return nil, errors.New("invalid audit snapshot")
	}
	return &snap, nil
}
func readSnapshotFile(dir, name string) ([]byte, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.ReadFile(name)
}

type driftFact struct{ source, subject, kind, value, evidence, quality string }
type driftIndex struct {
	facts      map[string]driftFact
	sources    map[string]topology.MapSource
	incomplete map[string]bool
	scopedTags map[string]bool
}

func stale(at, t time.Time, age time.Duration) bool {
	return t.IsZero() || t.After(at) || at.Sub(t) > age
}
func (c NetworkMapCapture) index(maxAge time.Duration) driftIndex {
	idx := driftIndex{facts: map[string]driftFact{}, sources: map[string]topology.MapSource{}, incomplete: map[string]bool{}, scopedTags: map[string]bool{}}
	sources := map[string]string{}
	ids := map[string]string{}
	owners := map[string]string{}
	types := map[string]string{}
	for _, s := range c.Map.Sources {
		k := stableMapRef("source", s.Provider, s.Profile)
		sources[s.ID] = k
		idx.sources[k] = s
	}
	for _, r := range c.Map.Resources {
		source := sources[r.Source]
		if source == "" || r.NativeID == "" {
			continue
		}
		k := stableMapRef("resource", source, r.Kind, r.NativeID)
		ids[r.ID] = k
		owners[r.ID] = source
		types[r.ID] = r.Kind
		if r.GatewayPrefix != "" {
			idx.facts[stableMapRef(k, "address")] = driftFact{source: source, subject: k, kind: "address", value: stableMapRef(r.GatewayPrefix), evidence: "configured gateway prefix"}
		}
	}
	for _, l := range c.Map.Links {
		ssidBinding := l.Relation == "segment" && types[l.From] == "ssid"
		if l.Relation != "tagged" && !ssidBinding {
			continue
		}
		subject := ids[l.From]
		if subject == "" {
			continue
		}
		family := stableMapRef(subject, l.Relation)
		if l.State != "observed" || len(l.Targets) != 1 || ids[l.Targets[0]] == "" {
			idx.incomplete[family] = true
			if l.Relation == "tagged" && l.Evidence == "effective port membership unavailable" {
				idx.scopedTags[owners[l.From]] = true
			}
			continue
		}
		target := ids[l.Targets[0]]
		k := family
		if l.Relation == "tagged" {
			k = stableMapRef(subject, l.Relation, target)
		}
		idx.facts[k] = driftFact{source: owners[l.From], subject: subject, kind: l.Relation, value: target, evidence: map[string]string{"segment": "SSID VLAN configuration", "tagged": "bound port profile"}[l.Relation]}
	}
	scope := make([]string, 0, len(idx.sources))
	for key := range idx.sources {
		scope = append(scope, key)
	}
	slices.Sort(scope)
	scopeKey := stableMapRef(scope...)
	for k, p := range c.Policies {
		k = stableMapRef(scopeKey, k)
		quality := ""
		if stale(c.At, p.RecordedAt, maxAge) {
			quality = "stale"
		} else if p.Declared != "allow" && p.Declared != "deny" {
			quality = "unverified"
		}
		evidence := "declared service policy, " + p.Firewall + " firewall evidence"
		idx.facts[k] = driftFact{source: "policy", subject: k, kind: "policy", value: p.Declared, evidence: evidence, quality: quality}
	}
	return idx
}
func (idx driftIndex) quality(at time.Time, f driftFact, maxAge time.Duration) string {
	if f.kind == "policy" {
		return f.quality
	}
	s, ok := idx.sources[f.source]
	if !ok {
		return "unavailable"
	}
	if s.ObservedAt != nil && stale(at, *s.ObservedAt, maxAge) {
		return "stale"
	}
	if idx.incomplete[stableMapRef(f.subject, f.kind)] {
		return "unverified"
	}
	for _, g := range s.Gaps {
		switch g {
		case "effective tagged VLANs":
			if f.kind == "tagged" && !idx.scopedTags[f.source] {
				return "unverified"
			}
		case "LAN profiles", "switch ports":
			if f.kind == "tagged" {
				return "unverified"
			}
		case "SSIDs":
			if f.kind == "segment" {
				return "unverified"
			}
		case "LLDP neighbors", "AP uplinks", "device identity", "devices":
			continue
		case "segments", "VLAN interfaces", "assigned interfaces":
			return "unverified"
		default:
			return "unavailable"
		}
	}
	return ""
}
func changeImpact(kind string) string {
	switch kind {
	case "tagged":
		return "tagged VLAN membership on this port changed"
	case "segment":
		return "wireless clients may enter a different VLAN"
	case "policy":
		return "declared service access changed"
	default:
		return "address churn observed"
	}
}
func CompareNetworkMaps(before, after NetworkMapCapture, maxAge time.Duration) NetworkDrift {
	a, b := before.index(maxAge), after.index(maxAge)
	report := NetworkDrift{Before: before.At, After: after.At, Changes: []MapChange{}}
	keys := map[string]bool{}
	for k := range a.facts {
		keys[k] = true
	}
	for k := range b.facts {
		keys[k] = true
	}
	for k := range keys {
		old, was := a.facts[k]
		next, now := b.facts[k]
		fact := next
		if !now {
			fact = old
		}
		quality := b.quality(after.At, fact, maxAge)
		if quality == "" {
			quality = a.quality(before.At, fact, maxAge)
		}
		if fact.kind == "policy" {
			if !was || !now {
				quality = "unavailable"
			} else if old.quality != "" {
				quality = old.quality
			}
		} else if c, d := a.sources[fact.source], b.sources[fact.source]; c.ControllerSite != "" && d.ControllerSite != "" && (c.ControllerSite != d.ControllerSite || c.LogicalSite != d.LogicalSite) {
			quality = "unverified"
		}
		if was && now && old.value == next.value && quality == "" {
			continue
		}
		row := MapChange{Reference: k, Subject: fact.subject, Impact: changeImpact(fact.kind), Evidence: fact.evidence, Previous: old.value, Current: next.value}
		switch {
		case quality != "":
			row.Change = quality
			row.Impact = "insufficient evidence for configuration drift"
		case fact.kind == "address":
			row.Change = "address_churn"
		case !was:
			row.Change = "added"
		case !now:
			row.Change = "removed"
		default:
			row.Change = "changed"
		}
		report.Changes = append(report.Changes, row)
	}
	for k, s := range b.sources {
		previous := a.sources[k]
		quality := ""
		switch {
		case s.ObservedAt != nil && stale(after.At, *s.ObservedAt, maxAge):
			quality = "stale"
		case len(s.Gaps) > 0 && !slices.Equal(previous.Gaps, s.Gaps):
			quality = "incomplete"
		}
		if quality != "" {
			report.Changes = append(report.Changes, MapChange{Reference: k, Subject: "source", Change: quality, Impact: "source coverage changed", Evidence: "collector status"})
		}
	}
	slices.SortFunc(report.Changes, func(a, b MapChange) int { return strings.Compare(a.Reference, b.Reference) })
	return report
}
