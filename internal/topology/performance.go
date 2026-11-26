package topology

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"time"
)

// PerformanceTarget identifies one operator-selected hop. Controller identities stay in this input.
type PerformanceTarget struct {
	Connection string `json:"connection"`
	Kind       string `json:"kind"`
	SwitchMAC  string `json:"switch_mac,omitempty"`
	APMAC      string `json:"ap_mac,omitempty"`
	Port       int    `json:"port,omitempty"`
	Band       string `json:"band,omitempty"`
	Channel    int    `json:"channel,omitempty"`
	Name       string `json:"name,omitempty"`
}

func ParsePerformancePath(text string) ([]PerformanceTarget, error) {
	var targets []PerformanceTarget
	dec := json.NewDecoder(strings.NewReader(text))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&targets); err != nil || len(targets) == 0 || len(targets) > 32 {
		return nil, errors.New("path must be a JSON array of 1 to 32 selected hops")
	}
	if err := dec.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, errors.New("path must contain one array")
	}
	for _, t := range targets {
		provider, profile, named := strings.Cut(t.Connection, "/")
		if !named || provider == "" || profile == "" || strings.Contains(profile, "/") {
			return nil, errors.New("each hop requires its provider/profile connection")
		}
		switch t.Kind {
		case "switch_port":
			mac, err := net.ParseMAC(t.SwitchMAC)
			if err != nil || len(mac) != 6 || t.Port < 1 {
				return nil, errors.New("a switch port needs a MAC and positive port number")
			}
		case "channel":
			if t.APMAC != "" {
				mac, err := net.ParseMAC(t.APMAC)
				if err != nil || len(mac) != 6 {
					return nil, errors.New("invalid AP MAC")
				}
			}
			if !slices.Contains([]string{"2g", "5g", "6g"}, t.Band) || t.Channel < 1 {
				return nil, errors.New("a channel needs band 2g, 5g or 6g and a channel number")
			}
		case "interface", "gateway", "shaper_queue":
			if t.Name == "" {
				return nil, errors.New("select the interface, gateway or queue name")
			}
		default:
			return nil, errors.New("unknown performance hop kind")
		}
	}
	return targets, nil
}

// PassiveSample preserves missing versus zero measurements. Rates reported by a
// controller are instantaneous; cumulative counters allow an interval average.
type PassiveSample struct {
	At              time.Time `json:"at"`
	Status          string    `json:"status"`
	ConfiguredSpeed *int      `json:"configured_link_speed_code,omitempty"`
	LinkUp          *bool     `json:"link_up,omitempty"`
	ObservedMbps    *int      `json:"observed_link_mbps,omitempty"`
	RxBytes         *uint64   `json:"rx_bytes,omitempty"`
	TxBytes         *uint64   `json:"tx_bytes,omitempty"`
	RxErrors        *uint64   `json:"rx_errors,omitempty"`
	TxErrors        *uint64   `json:"tx_errors,omitempty"`
	Drops           *uint64   `json:"flow_drops,omitempty"`
	FlowSet         string    `json:"-"`
	RxRate          *uint64   `json:"reported_rx_bps,omitempty"`
	TxRate          *uint64   `json:"reported_tx_bps,omitempty"`
	Utilization     *float64  `json:"channel_utilization_percent,omitempty"`
	Interference    *float64  `json:"interference_percent,omitempty"`
	LatencyMS       *float64  `json:"gateway_latency_ms,omitempty"`
	Loss            *float64  `json:"gateway_loss_percent,omitempty"`
}
type HopPerformance struct {
	Hop                int           `json:"hop"`
	Kind               string        `json:"kind"`
	Before             PassiveSample `json:"before"`
	After              PassiveSample `json:"after"`
	Status             string        `json:"status"`
	RxBPS              *float64      `json:"mean_rx_bps,omitempty"`
	TxBPS              *float64      `json:"mean_tx_bps,omitempty"`
	MeasuredThroughput *float64      `json:"measured_throughput_bps"`
	Finding            string        `json:"finding,omitempty"`
	Recommendation     string        `json:"recommendation,omitempty"`
}

func AssessHop(n int, kind string, a, b PassiveSample) HopPerformance {
	r := HopPerformance{Hop: n, Kind: kind, Before: a, After: b, Status: "insufficient_evidence"}
	elapsed := b.At.Sub(a.At).Seconds()
	if a.Status != "available" || b.Status != "available" || elapsed <= 0 {
		return r
	}
	if a.FlowSet != b.FlowSet {
		r.Status = "flow_set_changed"
		return r
	}
	pairs := [][2]*uint64{{a.RxBytes, b.RxBytes}, {a.TxBytes, b.TxBytes}, {a.RxErrors, b.RxErrors}, {a.TxErrors, b.TxErrors}, {a.Drops, b.Drops}}
	for _, pair := range pairs {
		if pair[0] != nil && pair[1] != nil && *pair[1] < *pair[0] {
			r.Status = "counter_reset"
			return r
		}
	}
	rate := func(first, last *uint64) *float64 {
		if first == nil || last == nil {
			return nil
		}
		v := float64(*last-*first) * 8 / elapsed
		return &v
	}
	r.RxBPS = rate(a.RxBytes, b.RxBytes)
	r.TxBPS = rate(a.TxBytes, b.TxBytes)
	increased := func(x, y *uint64) bool { return x != nil && y != nil && *y > *x }
	switch {
	case increased(a.RxErrors, b.RxErrors) || increased(a.TxErrors, b.TxErrors):
		r.Status = "observed"
		r.Finding = "switch error counters increased"
		r.Recommendation = "Check the cable and transceivers, then repeat this path and interval."
	case a.Interference != nil && b.Interference != nil && *a.Interference >= 50 && *b.Interference >= 50:
		r.Status = "observed"
		r.Finding = "the selected AP reported at least 50% interference utilization at both samples"
		r.Recommendation = "Compare channels on the same AP during the affected workload."
	case a.Utilization != nil && b.Utilization != nil && *a.Utilization >= 80 && *b.Utilization >= 80:
		r.Status = "observed"
		r.Finding = "channel utilization was at least 80% at both samples"
		r.Recommendation = "Compare nearby channel utilization during the same workload before changing channels."
	case increased(a.Drops, b.Drops):
		r.Status = "observed"
		r.Finding = "drops increased for the same queue flows"
		r.Recommendation = "Review the selected queue bandwidth and repeat the same path under load."
	case b.Loss != nil && *b.Loss > 0:
		r.Status = "observed"
		r.Finding = "the gateway monitor reported packet loss"
		r.Recommendation = "Compare this gateway monitor with the other hops during the same workload."
	case r.RxBPS != nil && r.TxBPS != nil && *r.RxBPS == 0 && *r.TxBPS == 0:
		r.Status = "idle"
	case r.RxBPS != nil || r.TxBPS != nil || b.RxRate != nil || b.TxRate != nil || b.Utilization != nil || b.Interference != nil || b.LatencyMS != nil || b.Loss != nil || b.Drops != nil || b.LinkUp != nil:
		r.Status = "observed"
	}
	return r
}
