package omada

import (
	"cmp"
	"context"
	"strconv"
	"strings"
	"time"
)

// ControllerFirmware reports a live update check or a published fallback.
type ControllerFirmware struct {
	Status    string `json:"status"`
	Current   string `json:"current_version,omitempty"`
	Latest    string `json:"latest_version,omitempty"`
	Reference string `json:"reference_version,omitempty"`
	Source    string `json:"source,omitempty"`
	Summary   string `json:"summary"`
}

type controllerFirmwareIdentity struct {
	Model     string `json:"model"`
	ModelName string `json:"modelName"`
	Revision  string `json:"modelVersion"`
	Firmware  string `json:"firmwareVersion"`
}

type controllerUpdate struct {
	Update  *bool  `json:"update"`
	Current string `json:"currentVersion"`
	Latest  string `json:"latestVersion"`
}

// CheckControllerFirmware queries the controller rather than relying on a
// vendor update hostname that may change or stop resolving.
func (c *Client) CheckControllerFirmware(ctx context.Context) ControllerFirmware {
	liveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var live controllerUpdate
	if err := c.get(liveCtx, "system/setting/hardware/check-firmware", &live); err == nil && live.Update != nil && live.Current != "" && live.Latest != "" {
		result := ControllerFirmware{Current: live.Current, Latest: live.Latest, Source: "controller"}
		if *live.Update {
			result.Status = "newer_available"
			result.Summary = "Controller reports newer firmware."
		} else {
			result.Status = "up_to_date"
			result.Summary = "Controller reports that firmware is up to date."
		}
		return result
	}

	identityCtx, cancelIdentity := context.WithTimeout(ctx, 5*time.Second)
	defer cancelIdentity()
	var identity controllerFirmwareIdentity
	_ = c.get(identityCtx, "system/setting/controller-status", &identity)
	return fallbackControllerFirmware(identity)
}

func fallbackControllerFirmware(identity controllerFirmwareIdentity) ControllerFirmware {
	result := ControllerFirmware{Status: "check_unreachable", Current: identity.Firmware, Summary: "Vendor check unavailable; no newer version known to nyx."}
	model := strings.ToUpper(strings.TrimSpace(identity.Model))
	name := strings.ToUpper(strings.TrimSpace(identity.ModelName))
	revision := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(identity.Revision)), "v")
	// The release note restricts this firmware to these market/revision pairs.
	// Unqualified controller identities cannot safely use the reference.
	switch {
	case (model == "OC200(UN)" || name == "OC200(UN)") && (revision == "3.0" || revision == "3.6"),
		(model == "OC200(IN)" || name == "OC200(IN)") && revision == "3.8":
		result.Reference = "3.4.25"
		result.Source = "published_reference"
		if firmwareVersionOlder(identity.Firmware, result.Reference) {
			result.Status = "newer_available"
			result.Summary = "Vendor check unavailable; published hardware firmware is newer."
		}
	}
	return result
}

func firmwareVersionOlder(current, reference string) bool {
	current, _, _ = strings.Cut(strings.TrimSpace(current), " ")
	installed := strings.Split(current, ".")
	published := strings.Split(reference, ".")
	if len(installed) != 3 || len(published) != 3 {
		return false
	}
	var comparison int
	for i := range installed {
		left, leftErr := strconv.ParseUint(installed[i], 10, 32)
		right, rightErr := strconv.ParseUint(published[i], 10, 32)
		if leftErr != nil || rightErr != nil {
			return false
		}
		if comparison == 0 {
			comparison = cmp.Compare(left, right)
		}
	}
	return comparison < 0
}
