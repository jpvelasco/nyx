package cli

import (
	"context"
	"fmt"
	"strings"

	"github.com/jpvelasco/nyx/internal/backends/omada"
	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/jpvelasco/nyx/internal/textsafe"
	"github.com/spf13/cobra"
)

const wlanZeroAPGuidance = "APs can be present while every band's candidate list is empty. Check the controller log for per-device RFPlanning exclusions."

func buildOmadaWLANOptimizationCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "wlan-optimization [history-id]",
		Short: "Read Omada WLAN optimization history and failure diagnostics",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			return withProviderSession("omada", func(ctx context.Context, opts providers.ImportOptions) error {
				svc := service.NewOmadaService()
				if len(args) == 1 {
					detail, err := svc.GetWLANOptimizationHistory(ctx, toOmadaOptions(opts), args[0])
					if err != nil {
						return err
					}
					return renderWLANOptimizationDetail(detail)
				}
				rows, err := svc.ListWLANOptimizationHistory(ctx, toOmadaOptions(opts))
				if err != nil {
					return err
				}
				return renderWLANOptimizationHistory(rows)
			})
		},
	}
	addProviderFlags(cmd, "omada")
	return cmd
}

func renderWLANOptimizationHistory(rows []omada.WLANOptimizationRun) error {
	type diagnostic struct {
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
	output := make([]diagnostic, 0, len(rows))
	for _, row := range rows {
		d := diagnostic{ID: row.ID, APCount: row.APCount, ScanSuccess: row.ScanSuccess, Code: row.MessageType, Message: textsafe.Message(row.Message), Status: omada.WLANOptimizationStatus(row.MessageType), Failed2G: failedWLANMACCount(row.Failed2G), Failed5G: failedWLANMACCount(row.Failed5G), Failed6G: failedWLANMACCount(row.Failed6G)}
		if row.APCount == 0 && row.MessageType == -34806 {
			d.Guidance = wlanZeroAPGuidance
		}
		output = append(output, d)
	}
	if jsonOutput {
		return printJSON(output)
	}
	if len(output) == 0 {
		fmt.Println("No WLAN optimization history found.")
	}
	for _, d := range output {
		fmt.Printf("%q  APs=%d  scan-success=%t  msgType=%d  %s %s\n", d.ID, d.APCount, d.ScanSuccess, d.Code, d.Status, d.Message)
		fmt.Printf("  Failed APs by band: 2.4 GHz=%d, 5 GHz=%d, 6 GHz=%d\n", d.Failed2G, d.Failed5G, d.Failed6G)
		if d.Guidance != "" {
			fmt.Println("  " + d.Guidance)
		}
	}
	return nil
}

func failedWLANMACCount(value string) int {
	return len(strings.FieldsFunc(value, func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t' }))
}

func renderWLANOptimizationDetail(detail omada.WLANOptimizationDetail) error {
	type diagnostic struct {
		AP          int            `json:"ap"`
		Message     string         `json:"fail_msg,omitempty"`
		MessageType *int           `json:"fail_msg_type,omitempty"`
		Trigger     *int           `json:"trigger_reason,omitempty"`
		RadioCodes  map[string]int `json:"radio_error_codes"`
	}
	rows := make([]diagnostic, 0, len(detail.Devices))
	for i, ap := range detail.Devices {
		d := diagnostic{AP: i + 1, Message: ap.SafeFailureMessage(), MessageType: ap.FailMessageType, Trigger: ap.TriggerReason, RadioCodes: make(map[string]int)}
		for band, radio := range map[string]*omada.WLANOptimizationRadio{"2.4 GHz": ap.Radio2G, "5 GHz": ap.Radio5G, "5 GHz-2": ap.Radio5G2, "6 GHz": ap.Radio6G} {
			if code := radio.Code(); code != nil {
				d.RadioCodes[band] = *code
			}
		}
		rows = append(rows, d)
	}
	if jsonOutput {
		return printJSON(struct {
			Success int          `json:"success_devices"`
			Failed  int          `json:"fail_devices"`
			APs     []diagnostic `json:"aps"`
		}{detail.SuccessDevices, detail.FailDevices, rows})
	}
	fmt.Printf("WLAN optimization APs: %d successful, %d failed\n", detail.SuccessDevices, detail.FailDevices)
	if len(rows) == 0 {
		fmt.Println("No per-AP details were recorded.")
	}
	for _, d := range rows {
		fmt.Printf("  AP %d", d.AP)
		if d.MessageType != nil {
			fmt.Printf("  failMsgType=%d", *d.MessageType)
		}
		if d.Trigger != nil {
			fmt.Printf("  triggerReason=%d", *d.Trigger)
		}
		if d.Message != "" {
			fmt.Printf("  %s", d.Message)
		}
		for _, band := range []string{"2.4 GHz", "5 GHz", "5 GHz-2", "6 GHz"} {
			if code, ok := d.RadioCodes[band]; ok {
				fmt.Printf("  %s errCode=%d", band, code)
			}
		}
		fmt.Println()
	}
	return nil
}
