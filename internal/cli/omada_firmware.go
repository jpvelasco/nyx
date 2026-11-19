package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/spf13/cobra"
)

func buildOmadaFirmwareCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "firmware", Short: "Manage Omada device firmware"}
	var file, mac, expected string
	var confirm bool
	upgrade := &cobra.Command{
		Use:   "upgrade",
		Short: "Preview or run a manual managed-device firmware upgrade",
		Long:  "Upgrade a managed site device with a local .bin image. Dry-run by default. This workflow cannot install an image on the controller itself.",
		RunE: func(_ *cobra.Command, _ []string) error {
			if !strings.EqualFold(filepath.Ext(file), ".bin") {
				return fmt.Errorf("--file must point to a managed-device .bin firmware image")
			}
			// #nosec G304 -- the operator explicitly selects the local image.
			image, err := os.Open(file)
			if err != nil {
				return err
			}
			defer image.Close()
			info, err := image.Stat()
			if err != nil {
				return err
			}
			if !info.Mode().IsRegular() || info.Size() == 0 {
				return fmt.Errorf("--file must be a nonempty regular firmware image")
			}
			return withProviderSession("omada", func(ctx context.Context, opts providers.ImportOptions) error {
				result, err := service.NewOmadaService().UpgradeDevice(ctx, toOmadaOptions(opts), mac, expected, image, confirm)
				if err != nil {
					return err
				}
				if jsonOutput {
					return printJSON(result)
				}
				fmt.Printf("%s: device %s firmware %q, expected %q, controller %q\n", result.Status, result.Device, result.ObservedFirmware, result.ExpectedFirmware, result.ControllerVersion)
				return nil
			})
		},
	}
	upgrade.Flags().StringVar(&file, "file", "", "Path to the managed-device .bin firmware image")
	upgrade.Flags().StringVar(&mac, "mac", "", "MAC address of the managed device")
	upgrade.Flags().StringVar(&expected, "expected-version", "", "Exact firmwareVersion expected after reboot")
	upgrade.Flags().BoolVar(&confirm, "confirm-reboot", false, "Upload and start firmware upgrade, rebooting the device")
	upgrade.Flags().StringVar(&providerSite, "site", "", "Site name (defaults to first site)")
	addProviderFlags(upgrade, "omada")
	cmd.AddCommand(upgrade)
	return cmd
}
