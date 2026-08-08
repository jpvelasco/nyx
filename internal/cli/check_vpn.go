package cli

import (
	"context"
	"fmt"

	"github.com/jpvelasco/nyx/internal/models"
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
		if vpnExpect != "" && vpnExpect != "full-tunnel" && vpnExpect != "split-tunnel" {
			return fmt.Errorf("invalid --expect %q: must be split-tunnel or full-tunnel", vpnExpect)
		}

		dur, err := parseTimeoutFlag(timeout)
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), dur)
		defer cancel()

		checkSvc := service.NewCheckService()
		result := checkSvc.CheckVPN(ctx, vpnTarget)

		applyVPNExpect(result, vpnExpect)
		result.Finish()

		w, err := getWriter()
		if err != nil {
			return err
		}
		if outputPath != "" {
			defer w.Close()
		}

		return renderCheckResult(w, result)
	},
}

// applyVPNExpect compares the observed tunnel state against --expect and
// overrides the verdict accordingly. full-tunnel requires traffic through the
// tunnel; split-tunnel requires traffic NOT forced through it. The comparison
// is only meaningful when CheckVPN produced a definite routing verdict
// (Pass or Warn) — errored lookups are left untouched.
func applyVPNExpect(result *models.CheckResult, expect string) {
	if expect == "" || (result.Status != models.StatusPass && result.Status != models.StatusWarn) {
		return
	}
	viaTunnel, _ := result.Observed["via_tunnel"].(bool)
	expectTunnel := expect == "full-tunnel"
	if viaTunnel == expectTunnel {
		if !viaTunnel {
			result.Status = models.StatusPass
			result.Summary = fmt.Sprintf("%s routes via %s (split-tunnel: not forced through tunnel)", result.Target, result.Observed["device"])
		}
		return
	}
	result.Status = models.StatusFail
	if expectTunnel {
		result.Summary = fmt.Sprintf("%s NOT routed via tunnel (using %s)", result.Target, result.Observed["device"])
		result.Violations = append(result.Violations, "expected full-tunnel routing but traffic uses non-tunnel interface")
	} else {
		result.Summary = fmt.Sprintf("%s forced through tunnel despite split-tunnel expectation (using %s)", result.Target, result.Observed["device"])
		result.Violations = append(result.Violations, "expected split-tunnel routing but traffic uses tunnel interface")
	}
}

func init() {
	checkVPNCmd.Flags().StringVar(&vpnTarget, "target", "", "Target IP to check VPN routing for")
	checkVPNCmd.Flags().StringVar(&vpnExpect, "expect", "", "Expected tunnel mode (split-tunnel or full-tunnel)")
}
