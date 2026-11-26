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
			image, err := openFirmwareImage(file)
			if err != nil {
				return err
			}
			defer image.Close()
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
	cmd.AddCommand(upgrade, buildStageFirmwareCmd(), buildStagedFirmwareCmd())
	return cmd
}

func openFirmwareImage(file string) (*os.File, error) {
	if !strings.EqualFold(filepath.Ext(file), ".bin") {
		return nil, fmt.Errorf("--file must point to a managed-device .bin firmware image")
	}
	// #nosec G304 -- the operator explicitly selects the local image.
	image, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	info, err := image.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		_ = image.Close()
		return nil, fmt.Errorf("--file must be a nonempty regular firmware image")
	}
	return image, nil
}
func buildStageFirmwareCmd() *cobra.Command {
	var file, mac, version string
	cmd := &cobra.Command{Use: "stage", Short: "Stage a private managed-device image for the configured target and site", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, _ []string) error {
		image, err := openFirmwareImage(file)
		if err != nil {
			return err
		}
		defer image.Close()
		return withProviderSession("omada", func(ctx context.Context, opts providers.ImportOptions) error {
			ref, err := service.NewOmadaService().StageFirmware(ctx, toOmadaOptions(opts), service.FirmwareStageDir(), mac, version, image)
			if err != nil {
				return err
			}
			return printJSON(map[string]string{"reference": ref})
		})
	}}
	cmd.Flags().StringVar(&file, "file", "", "Local managed-device firmware image")
	cmd.Flags().StringVar(&mac, "mac", "", "Exact managed device MAC")
	cmd.Flags().StringVar(&version, "expected-version", "", "Expected version after reboot")
	cmd.Flags().StringVar(&providerSite, "site", "", "Explicit Omada site")
	addProviderFlags(cmd, "omada")
	return cmd
}

func buildStagedFirmwareCmd() *cobra.Command {
	var ref string
	var confirm bool
	cmd := &cobra.Command{Use: "staged", Short: "Preview or confirm the upgrade tied to an operator-staged reference", Args: cobra.NoArgs, RunE: func(_ *cobra.Command, _ []string) error {
		return withProviderSession("omada", func(ctx context.Context, opts providers.ImportOptions) error {
			r, err := service.NewOmadaService().UpgradeStagedFirmware(ctx, toOmadaOptions(opts), service.FirmwareStageDir(), ref, confirm)
			if err != nil {
				return err
			}
			return printJSON(r)
		})
	}}
	cmd.Flags().StringVar(&ref, "reference", "", "Opaque reference returned by firmware stage")
	cmd.Flags().BoolVar(&confirm, "confirm-reboot", false, "Authorize reboot on a supported model")
	cmd.Flags().StringVar(&providerSite, "site", "", "Explicit Omada site")
	addProviderFlags(cmd, "omada")
	return cmd
}
