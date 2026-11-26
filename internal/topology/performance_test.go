package topology

import (
	"testing"
	"time"
)

func TestPerformanceEvidence(t *testing.T) {
	now := time.Now()
	one, two, three := uint64(1), uint64(2), uint64(3)
	high, low := 85.0, 12.0
	for _, tc := range []struct {
		name, kind, status, finding string
		a, b                        PassiveSample
	}{
		{"wired errors", "switch_port", "observed", "switch error counters increased", PassiveSample{RxErrors: &one, RxBytes: &one}, PassiveSample{RxErrors: &two, RxBytes: &three}},
		{"congested WLAN", "channel", "observed", "channel utilization was at least 80% at both samples", PassiveSample{Utilization: &high}, PassiveSample{Utilization: &high}},
		{"low interference", "channel", "observed", "", PassiveSample{Interference: &low}, PassiveSample{Interference: &low}},
		{"missing", "interface", "insufficient_evidence", "", PassiveSample{}, PassiveSample{}},
		{"counter reset", "interface", "counter_reset", "", PassiveSample{RxBytes: &three}, PassiveSample{RxBytes: &one}},
		{"idle", "interface", "idle", "", PassiveSample{RxBytes: &one, TxBytes: &one}, PassiveSample{RxBytes: &one, TxBytes: &one}},
		{"queue flow churn", "shaper_queue", "flow_set_changed", "", PassiveSample{FlowSet: "old", Drops: &two}, PassiveSample{FlowSet: "new", Drops: &one}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.a.At = now
			tc.b.At = now.Add(2 * time.Second)
			tc.a.Status = "available"
			tc.b.Status = "available"
			r := AssessHop(1, tc.kind, tc.a, tc.b)
			if r.Status != tc.status || r.Finding != tc.finding || r.MeasuredThroughput != nil {
				t.Fatal(r)
			}
			if tc.name == "wired errors" && (r.RxBPS == nil || *r.RxBPS != 8) {
				t.Fatal("wrong bit rate")
			}
		})
	}
}

func TestPerformanceSelectorsAndGatewayEvidence(t *testing.T) {
	for _, text := range []string{`[]`, `[] {}`, `[{"connection":"/home","kind":"gateway","name":"gw"}]`, `[{"connection":"a/home/lab","kind":"gateway","name":"gw"}]`, `[{"kind":"interface"}]`, `[{"connection":"a/home","kind":"interface"}]`, `[{"connection":"a/home","kind":"switch_port","switch_mac":"bad","port":1}]`, `[{"connection":"a/home","kind":"channel","band":"5g","channel":36,"ap_mac":"bad"}]`, `[{"connection":"a/home","kind":"channel","band":"bad","channel":36}]`, `[{"connection":"a/home","kind":"bad"}]`} {
		if _, err := ParsePerformancePath(text); err == nil {
			t.Fatalf("bad selector accepted: %s", text)
		}
	}
	for _, text := range []string{`[{"connection":"a/home","kind":"gateway","name":"gw"}]`, `[{"connection":"a/home","kind":"channel","band":"5g","channel":36,"ap_mac":"02:aa:bb:cc:dd:03"}]`, `[{"connection":"a/home","kind":"switch_port","port":8,"switch_mac":"02:aa:bb:cc:dd:02"}]`} {
		if _, err := ParsePerformancePath(text); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now()
	base := PassiveSample{At: now, Status: "available"}
	next := base
	next.At = now.Add(time.Second)
	loss, inter := 2.0, 52.0
	first, last := uint64(2), uint64(3)
	for _, tc := range []struct {
		kind string
		set  func(a, b *PassiveSample)
	}{{"gateway", func(a, b *PassiveSample) { b.Loss = &loss }},
		{"channel", func(a, b *PassiveSample) { a.Interference = &inter; b.Interference = &inter }},
		{"shaper_queue", func(a, b *PassiveSample) { a.Drops = &first; b.Drops = &last }}} {
		a, b := base, next
		tc.set(&a, &b)
		r := AssessHop(1, tc.kind, a, b)
		if r.Recommendation == "" || r.Finding == "" {
			t.Fatal(r)
		}
	}
}
