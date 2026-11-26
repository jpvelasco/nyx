package opnsense

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/topology"
	"slices"
	"strconv"
	"strings"
	"time"
)

func (*Provider) ObservePerformance(ctx context.Context, opts providers.ImportOptions, target topology.PerformanceTarget) (topology.PassiveSample, error) {
	s := topology.PassiveSample{Status: "unsupported"}
	if err := requireAuth(opts); err != nil {
		return s, err
	}
	c := newProviderClient(opts)
	switch target.Kind {
	case "interface":
		rows, err := c.GetInterfaces(ctx)
		if err != nil {
			return s, err
		}
		for _, row := range rows {
			if row.Name == target.Name {
				s.Status = "available"
				s.RxBytes = row.ReportedRxBytes
				s.TxBytes = row.ReportedTxBytes
				break
			}
		}
	case "gateway":
		rows, err := c.GetGatewayStatus(ctx)
		if err != nil {
			return s, err
		}
		for _, r := range rows {
			if r.Name == target.Name {
				s.Status = "available"
				s.LatencyMS = readMetric(r.Delay, "ms")
				s.Loss = readMetric(r.Loss, "%")
				if s.Loss != nil && *s.Loss > 100 {
					s.Loss = nil
				}
				break
			}
		}
	case "shaper_queue":
		sample, err := c.sampleQueue(ctx, target.Name)
		if err != nil {
			return s, err
		}
		s = sample
	}
	s.At = time.Now().UTC()
	return s, nil
}
func readMetric(text, unit string) *float64 {
	text = strings.TrimSpace(text)
	v, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(text, unit)), 64)
	if err != nil || v < 0 || !(v <= 1e20) {
		return nil
	}
	return &v
}
func (c *Client) sampleQueue(ctx context.Context, id string) (topology.PassiveSample, error) {
	s := topology.PassiveSample{Status: "unsupported"}
	resp, err := c.doRequest(ctx, "/trafficshaper/service/statistics")
	if err != nil {
		return s, err
	}
	defer resp.Body.Close()
	var env struct {
		Status string `json:"status"`
		Items  []struct {
			ID    string `json:"id"`
			Type  string `json:"type"`
			Flows []struct {
				Source      string  `json:"Source"`
				Destination string  `json:"Destination"`
				Protocol    string  `json:"Prot"`
				FlowID      string  `json:"flowid"`
				Drops       *uint64 `json:"drop_pkt"`
			} `json:"flows"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return s, err
	}
	if env.Status != "ok" {
		return s, nil
	}
	for _, r := range env.Items {
		if r.Type != "queue" || r.ID != id || r.Flows == nil {
			continue
		}
		var drops uint64
		var refs []string
		for _, f := range r.Flows {
			if f.Drops == nil || f.Source == "" || f.Destination == "" {
				return s, nil
			}
			raw, _ := json.Marshal([]string{f.Source, f.Destination, f.Protocol, f.FlowID})
			h := sha256.Sum256(raw)
			refs = append(refs, hex.EncodeToString(h[:]))
			drops += *f.Drops
		}
		slices.Sort(refs)
		s.FlowSet = strings.Join(refs, ",")
		s.Status = "available"
		s.Drops = &drops
		return s, nil
	}
	return s, nil
}
