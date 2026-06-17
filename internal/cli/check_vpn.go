package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/report"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/spf13/cobra"
)

var (
	vpnTarget string
	vpnExpect string
)

var checkVPNCmd = &cobra.Command{
	Use:   "check-vpn",
	Short: "Verify VPN status and routing",
	Example: `  nyx check-vpn --target 10.0.20.15
  nyx check-vpn --target 10.0.20.15 --json`,
	RunE: func(_ *cobra.Command, _ []string) error {
		if vpnTarget == "" {
			return fmt.Errorf("--target is required")
		}

		dur, err := time.ParseDuration(timeout)
		if err != nil {
			dur = 60 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), dur)
		defer cancel()

		checkSvc := service.NewCheckService()
		result := checkSvc.CheckVPN(ctx, vpnTarget)

		// Override with --expect flag if provided
		if vpnExpect != "" && result.Status == models.StatusWarn {
			result.Status = models.StatusFail
			result.Summary = fmt.Sprintf("%s NOT routed via tunnel (using %s)", vpnTarget, result.Observed["device"])
			result.Violations = append(result.Violations, "expected tunnel routing but traffic uses non-tunnel interface")
		}
		result.Finish()

		w, err := getWriter()
		if err != nil {
			return err
		}
		if outputPath != "" {
			defer w.Close()
		}

		if jsonOutput {
			return report.RenderResultJSON(w, result)
		}
		report.RenderResultHuman(w, result)
		return nil
	},
}

func init() {
	checkVPNCmd.Flags().StringVar(&vpnTarget, "target", "", "Target IP to check VPN routing for")
	checkVPNCmd.Flags().StringVar(&vpnExpect, "expect", "", "Expected tunnel mode (split-tunnel or full-tunnel)")
}
