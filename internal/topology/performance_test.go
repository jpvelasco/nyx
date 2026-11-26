package topology

import (
	"testing"
	"time"
)

func TestPerformanceEvidence(t *testing.T) {
	now := time.Now()
	one, two, three := uint64(1), uint64(2), uint64(3)
	high := 85.0
	for _, tc := range []struct {
		name, kind, status, finding string
		a, b                        PassiveSample
	}{
		{"wired errors", "switch_port", "observed", "switch error counters increased", PassiveSample{RxErrors: &one, RxBytes: &one}, PassiveSample{RxErrors: &two, RxBytes: &three}}, {"congested WLAN", "channel", "observed", "channel utilization was at least 80% at both samples", PassiveSample{Utilization: &high}, PassiveSample{Utilization: &high}}, {"missing", "interface", "insufficient_evidence", "", PassiveSample{}, PassiveSample{}}, {"counter reset", "interface", "counter_reset", "", PassiveSample{RxBytes: &three}, PassiveSample{RxBytes: &one}}, {"idle", "interface", "idle", "", PassiveSample{RxBytes: &one, TxBytes: &one}, PassiveSample{RxBytes: &one, TxBytes: &one}}, {"queue flow churn", "shaper_queue", "flow_set_changed", "", PassiveSample{FlowSet: "old", Drops: &one}, PassiveSample{FlowSet: "new", Drops: &two}}} {
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
