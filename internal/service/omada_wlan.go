package service

import (
	"context"
	"strings"

	"github.com/jpvelasco/nyx/internal/backends/omada"
	"github.com/jpvelasco/nyx/internal/textsafe"
)

func (s *OmadaService) ListWLANOptimizationHistory(ctx context.Context, opts OmadaOptions) ([]omada.WLANOptimizationRun, error) {
	return withSession(s, ctx, opts, func(c *omada.Client, siteID string) ([]omada.WLANOptimizationRun, error) {
		return c.ListWLANOptimizationHistory(ctx, siteID)
	})
}

func (s *OmadaService) GetWLANOptimizationHistory(ctx context.Context, opts OmadaOptions, historyID string) (omada.WLANOptimizationDetail, error) {
	return withSession(s, ctx, opts, func(c *omada.Client, siteID string) (omada.WLANOptimizationDetail, error) {
		return c.GetWLANOptimizationHistory(ctx, siteID, historyID)
	})
}

type WLANRunDiagnostic struct {
	ID          string `json:"id"`
	APCount     int    `json:"ap_count"`
	ScanSuccess bool   `json:"scan_success"`
	Code        int    `json:"msg_type"`
	Message     string `json:"msg"`
	Status      string `json:"status,omitempty"`
	Failed2G    int    `json:"failed_2g"`
	Failed5G    int    `json:"failed_5g"`
	Failed6G    int    `json:"failed_6g"`
	Guidance    string `json:"guidance,omitempty"`
}

func WLANRunDiagnostics(rows []omada.WLANOptimizationRun) []WLANRunDiagnostic {
	output := make([]WLANRunDiagnostic, 0, len(rows))
	for _, row := range rows {
		d := WLANRunDiagnostic{ID: row.ID, APCount: row.APCount, ScanSuccess: row.ScanSuccess, Code: row.MessageType, Message: textsafe.Message(row.Message), Status: omada.WLANOptimizationStatus(row.MessageType), Failed2G: failedWLANMACCount(row.Failed2G), Failed5G: failedWLANMACCount(row.Failed5G), Failed6G: failedWLANMACCount(row.Failed6G)}
		if row.APCount == 0 && row.MessageType == -34806 {
			d.Guidance = "APs can be present while every band's candidate list is empty. Check the controller log for per-device RFPlanning exclusions."
		}
		output = append(output, d)
	}
	return output
}
func failedWLANMACCount(value string) int {
	return len(strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t' }))
}

type WLANAPDiagnostic struct {
	AP          int            `json:"ap"`
	Message     string         `json:"fail_msg,omitempty"`
	MessageType *int           `json:"fail_msg_type,omitempty"`
	Trigger     *int           `json:"trigger_reason,omitempty"`
	RadioCodes  map[string]int `json:"radio_error_codes"`
}

func WLANAPDiagnostics(detail omada.WLANOptimizationDetail) []WLANAPDiagnostic {
	rows := make([]WLANAPDiagnostic, 0, len(detail.Devices))
	for i, ap := range detail.Devices {
		d := WLANAPDiagnostic{AP: i + 1, Message: ap.SafeFailureMessage(), MessageType: ap.FailMessageType, Trigger: ap.TriggerReason, RadioCodes: make(map[string]int)}
		for band, radio := range map[string]*omada.WLANOptimizationRadio{"2.4 GHz": ap.Radio2G, "5 GHz": ap.Radio5G, "5 GHz-2": ap.Radio5G2, "6 GHz": ap.Radio6G} {
			if code := radio.Code(); code != nil {
				d.RadioCodes[band] = *code
			}
		}
		rows = append(rows, d)
	}
	return rows
}
