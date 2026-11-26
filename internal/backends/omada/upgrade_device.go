package omada

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const MaxDeviceFirmwareBytes = 64 << 20

// DeviceUpgrade describes a verified firmware workflow against one site device.
type DeviceUpgrade struct {
	Status            string `json:"status"`
	Device            string `json:"device"`
	ExpectedFirmware  string `json:"expected_firmware"`
	ObservedFirmware  string `json:"observed_firmware"`
	ControllerVersion string `json:"controller_version"`
	TaskID            string `json:"task_id,omitempty"`
}

// UpgradeDevice verifies the chosen device and, if confirmed, starts one
// manual upgrade and waits for the expected firmware to appear in inventory.
func (c *Client) UpgradeDevice(ctx context.Context, siteID, mac, expected string, image io.Reader, confirmed bool) (DeviceUpgrade, error) {
	parsed, err := net.ParseMAC(mac)
	if err != nil || len(parsed) != 6 || strings.TrimSpace(expected) == "" || image == nil {
		return DeviceUpgrade{}, fmt.Errorf("device upgrade requires a MAC address, expected firmware version, and local image")
	}
	result := DeviceUpgrade{Status: "dry_run", Device: parsed.String(), ExpectedFirmware: strings.TrimSpace(expected), ControllerVersion: c.Info().ControllerVer}
	result.ObservedFirmware, err = c.deviceFirmware(ctx, siteID, result.Device)
	if err != nil || !confirmed {
		return result, err
	}
	if result.ObservedFirmware == result.ExpectedFirmware {
		result.Status = "already_current"
		return result, nil
	}
	result.Status = "unverified"
	fileID, err := c.uploadDeviceFirmware(ctx, siteID, image)
	if err != nil {
		return result, fmt.Errorf("uploading device image: %w", err)
	}
	start := struct {
		MACs   []string `json:"macs"`
		FileID string   `json:"fileId"`
	}{[]string{strings.ToUpper(strings.ReplaceAll(result.Device, ":", "-"))}, fileID}
	body, err := json.Marshal(start)
	if err != nil {
		return result, err
	}
	var task struct {
		ID string `json:"taskId"`
	}
	base := fmt.Sprintf("sites/%s/multi-devices", url.PathEscape(siteID))
	if err := c.doCreate(ctx, http.MethodPost, base+"/start-manually-upgrade", body, &task); err != nil {
		return result, fmt.Errorf("starting device firmware upgrade: %w", err)
	}
	if task.ID == "" {
		return result, fmt.Errorf("the controller did not return an upgrade task ID; check the device before retrying")
	}
	result.TaskID = task.ID
	if err := c.waitDeviceUpgrade(ctx, siteID, base+"/manually-upgrade-tasks/"+url.PathEscape(task.ID), &result); err != nil {
		return result, fmt.Errorf("upgrade task %q was not verified: %w", task.ID, err)
	}
	result.Status = "verified"
	return result, nil
}

func (c *Client) uploadDeviceFirmware(ctx context.Context, siteID string, image io.Reader) (string, error) {
	var body bytes.Buffer
	form := multipart.NewWriter(&body)
	part, err := form.CreateFormFile("file", "firmware.bin")
	if err != nil {
		return "", err
	}
	n, err := io.Copy(part, io.LimitReader(image, MaxDeviceFirmwareBytes+1))
	if err != nil {
		return "", err
	}
	if n == 0 || n > MaxDeviceFirmwareBytes {
		return "", fmt.Errorf("image must contain 1 to %d bytes", MaxDeviceFirmwareBytes)
	}
	if err := form.Close(); err != nil {
		return "", err
	}
	path := fmt.Sprintf("sites/%s/devices/upgrade-file", url.PathEscape(siteID))
	var uploaded struct {
		ID string `json:"fileId"`
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.doRequestLocked(ctx, http.MethodPost, c.requestURL(path), path, form.FormDataContentType(), body.Bytes(), &uploaded, true, true); err != nil {
		return "", err
	}
	if uploaded.ID == "" {
		return "", fmt.Errorf("the controller did not return an image ID")
	}
	return uploaded.ID, nil
}

func (c *Client) waitDeviceUpgrade(ctx context.Context, siteID, path string, result *DeviceUpgrade) error {
	for finished := false; ; {
		if !finished {
			var task struct {
				Finished bool `json:"finished"`
			}
			if err := c.get(ctx, path, &task); err == nil {
				finished = task.Finished
			}
		}
		if finished && c.verifyDeviceFirmware(ctx, siteID, result) {
			return nil
		}
		if err := sleepCtx(ctx, 2*time.Second); err != nil {
			return fmt.Errorf("expected firmware %q, last observed %q, controller %q: %w", result.ExpectedFirmware, result.ObservedFirmware, result.ControllerVersion, err)
		}
	}
}

func (c *Client) verifyDeviceFirmware(ctx context.Context, siteID string, result *DeviceUpgrade) bool {
	if firmware, err := c.deviceFirmware(ctx, siteID, result.Device); err == nil {
		result.ObservedFirmware = firmware
	} else {
		return false
	}
	info, err := c.fetchInfo(ctx)
	if err != nil || info.ControllerVer == "" {
		return false
	}
	result.ControllerVersion = info.ControllerVer
	return result.ObservedFirmware == result.ExpectedFirmware
}

func (c *Client) deviceFirmware(ctx context.Context, siteID, mac string) (string, error) {
	d, err := c.ManagedDevice(ctx, siteID, mac)
	return strings.TrimSpace(d.FirmwareVersion), err
}

// ManagedDevice finds one exact MAC in the selected site inventory.
func (c *Client) ManagedDevice(ctx context.Context, siteID, mac string) (Device, error) {
	devices, err := c.GetDevices(ctx, siteID)
	if err != nil {
		return Device{}, err
	}
	for _, candidate := range devices {
		if parsed, err := net.ParseMAC(candidate.MAC); err == nil && parsed.String() == mac {
			return candidate, nil
		}
	}
	return Device{}, fmt.Errorf("the target device was not found in the selected site")
}
