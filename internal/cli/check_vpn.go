package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/velasco-jp/netaudit/internal/backends/system"
	"github.com/velasco-jp/netaudit/internal/models"
	"github.com/velasco-jp/netaudit/internal/report"
)

var (
	vpnTarget string
	vpnExpect string
)

var checkVPNCmd = &cobra.Command{
	Use:   "check-vpn",
	Short: "Verify VPN status and routing",
	Example: `  netaudit check-vpn --target 10.0.20.15
  netaudit check-vpn --target 10.0.20.15 --json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if vpnTarget == "" {
			return fmt.Errorf("--target is required")
		}

		dur, err := time.ParseDuration(timeout)
		if err != nil {
			dur = 60 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), dur)
		defer cancel()

		result := models.NewCheckResult("system", "vpn_check", "local", vpnTarget)

		route, err := system.GetRouteToTarget(ctx, vpnTarget)
		if err != nil {
			result.Status = models.StatusError
			result.Summary = fmt.Sprintf("failed to get route: %v", err)
			result.Finish()
		} else {
			result.Observed["device"] = route.Device
			result.Observed["gateway"] = route.Gateway

			isVPN, _ := system.CheckVPNInterface(ctx, route.Device)
			result.Observed["via_tunnel"] = isVPN

			if isVPN {
				result.Status = models.StatusPass
				result.Summary = fmt.Sprintf("%s routed via tunnel interface %s", vpnTarget, route.Device)
			} else {
				if vpnExpect == "split-tunnel" || vpnExpect == "full-tunnel" {
					result.Status = models.StatusFail
					result.Summary = fmt.Sprintf("%s NOT routed via tunnel (using %s)", vpnTarget, route.Device)
					result.Violations = append(result.Violations, "expected tunnel routing but traffic uses non-tunnel interface")
				} else {
					result.Status = models.StatusPass
					result.Summary = fmt.Sprintf("%s routed via %s (not a tunnel interface)", vpnTarget, route.Device)
				}
			}
			result.Finish()
		}

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
