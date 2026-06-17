package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jpvelasco/nyx/internal/backends/system"
	"github.com/jpvelasco/nyx/internal/report"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/spf13/cobra"
)

var (
	routeTarget string
)

var checkRoutesCmd = &cobra.Command{
	Use:   "check-routes",
	Short: "Validate routes and gateways for targets",
	Example: `  nyx check-routes --target 10.0.30.10
  nyx check-routes --target 1.1.1.1 --json`,
	RunE: func(_ *cobra.Command, _ []string) error {
		if routeTarget == "" {
			return fmt.Errorf("--target is required")
		}

		dur, err := time.ParseDuration(timeout)
		if err != nil {
			dur = 60 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), dur)
		defer cancel()

		checkSvc := service.NewCheckService()
		result := checkSvc.CheckRoute(ctx, routeTarget)

		// Also get full route table if verbose
		if verbose {
			routes, routeErr := system.GetRoutes(ctx)
			if routeErr == nil {
				routeData, _ := json.Marshal(routes)
				result.Evidence = append(result.Evidence, string(routeData))
			}
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
	checkRoutesCmd.Flags().StringVar(&routeTarget, "target", "", "Target IP to check route for")
}
