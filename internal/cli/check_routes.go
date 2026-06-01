package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/jpvelasco/nyx/internal/backends/system"
	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/report"
)

var (
	routeTarget string
)

var checkRoutesCmd = &cobra.Command{
	Use:   "check-routes",
	Short: "Validate routes and gateways for targets",
	Example: `  nyx check-routes --target 10.0.30.10
  nyx check-routes --target 1.1.1.1 --json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if routeTarget == "" {
			return fmt.Errorf("--target is required")
		}

		dur, err := time.ParseDuration(timeout)
		if err != nil {
			dur = 60 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), dur)
		defer cancel()

		result := models.NewCheckResult("system", "route_check", "local", routeTarget)

		route, err := system.GetRouteToTarget(ctx, routeTarget)
		if err != nil {
			result.Status = models.StatusError
			result.Summary = fmt.Sprintf("failed to get route: %v", err)
			result.Finish()
		} else {
			result.Observed["gateway"] = route.Gateway
			result.Observed["device"] = route.Device
			result.Observed["destination"] = route.Destination
			result.Status = models.StatusPass
			result.Summary = fmt.Sprintf("route to %s via %s dev %s", routeTarget, route.Gateway, route.Device)
			result.Finish()

			// Also get full route table if verbose
			if verbose {
				routes, routeErr := system.GetRoutes(ctx)
				if routeErr == nil {
					routeData, _ := json.Marshal(routes)
					result.Evidence = append(result.Evidence, string(routeData))
				}
			}
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
	checkRoutesCmd.Flags().StringVar(&routeTarget, "target", "", "Target IP to check route for")
}
