package cli

import (
	"context"
	"fmt"

	"github.com/jpvelasco/nyx/internal/backends/omada"
	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/service"

	"github.com/spf13/cobra"
)

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
	output := service.WLANRunDiagnostics(rows)
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

func renderWLANOptimizationDetail(detail omada.WLANOptimizationDetail) error {
	rows := service.WLANAPDiagnostics(detail)
	if jsonOutput {
		return printJSON(struct {
			Success int                        `json:"success_devices"`
			Failed  int                        `json:"fail_devices"`
			APs     []service.WLANAPDiagnostic `json:"aps"`
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
