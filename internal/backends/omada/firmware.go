package omada

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	firmwareCurrent = "up_to_date"
	firmwareUpdate  = "update_available"
	firmwareEOL     = "eol"
	firmwareUnknown = "eol_or_current-unknown"
)

// US EAP620 HD revisions 1.0 and 1.6 ended sales on 2022-09-30.
// TP-Link's non-campus maintenance policy adds three years to that date.
var eap620HDUSV1MaintenanceEnd = time.Date(2025, 9, 30, 0, 0, 0, 0, time.UTC)

type firmwareInfo struct {
	Current string `json:"curFwVer"`
	Latest  string `json:"lastFwVer"`
}

func (c *Client) observeDeviceFirmware(ctx context.Context, siteID string, devices []Device) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for i := range devices {
		device := &devices[i]
		info := firmwareInfo{Current: device.FirmwareVersion, Latest: device.LatestVersion}
		if device.FirmwareStatus == firmwareUnknown && ctx.Err() == nil {
			// A validated MAC prevents controller-supplied path characters from
			// redirecting the request to a different operation.
			if mac, err := net.ParseMAC(device.MAC); err == nil && len(mac) == 6 {
				path := fmt.Sprintf("sites/%s/devices/%s/latest-firmware-info", siteID, strings.ToUpper(strings.ReplaceAll(mac.String(), ":", "-")))
				var latest firmwareInfo
				if err := c.get(ctx, path, &latest); err == nil && latest.Latest != "" {
					info = latest
				}
			}
		}
		device.FirmwareStatus, device.FirmwareAdvisory = classifyDeviceFirmware(*device, info, time.Now())
	}
}

func classifyDeviceFirmware(device Device, info firmwareInfo, now time.Time) (status, advisory string) {
	if eap620HDUSV1(device) && !now.Before(eap620HDUSV1MaintenanceEnd) {
		return firmwareEOL, "Regular maintenance ended in the US. Consider an EAP650 or another supported ceiling-mount Omada AP."
	}
	if device.NeedUpgrade {
		return firmwareUpdate, ""
	}
	current, latest := strings.TrimSpace(info.Current), strings.TrimSpace(info.Latest)
	if current == "" || latest == "" {
		return firmwareUnknown, ""
	}
	if current == latest {
		return firmwareCurrent, ""
	}
	return firmwareUpdate, ""
}

func eap620HDUSV1(device Device) bool {
	// The inventory schema identifies the market and revision in the
	// qualified display or compound AP model. A bare model is ambiguous.
	for _, raw := range []string{device.ShowModel, device.CompoundModel} {
		switch strings.ToLower(strings.Join(strings.Fields(raw), " ")) {
		case "eap620 hd(us) v1.0", "eap620 hd(us) v1.6":
			return true
		}
	}
	return false
}
