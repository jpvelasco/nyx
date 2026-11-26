package omada

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// PendingDevice includes only fields used to select and observe adoption.
type PendingDevice struct {
	MAC          string `json:"mac,omitempty"`
	Type         string `json:"type,omitempty"`
	DetailStatus int    `json:"detailStatus,omitempty"`
}

type PendingDevices struct {
	Total   int             `json:"totalRows"`
	Page    int             `json:"currentPage"`
	Devices []PendingDevice `json:"data"`
}

// PendingDevices reads one bounded page of the selected site's pending-device grid.
func (c *Client) PendingDevices(ctx context.Context, siteID string, page, size int, selected string) (PendingDevices, error) {
	var out PendingDevices
	if page < 1 || size < 1 || size > 100 {
		return out, errors.New("page must be positive and page size must be 1 to 100")
	}
	path := fmt.Sprintf("sites/%s/grid/devices/pending?page=%d&pageSize=%d", url.PathEscape(siteID), page, size)
	if selected != "" {
		path += "&searchKey=" + url.QueryEscape(selected)
	}
	if err := c.get(ctx, path, &out); err != nil {
		return out, err
	}
	if out.Devices == nil || len(out.Devices) > size || out.Total < len(out.Devices) || (out.Page != page && (out.Page != 0 || out.Total != 0)) {
		return PendingDevices{}, errors.New("invalid pending-device page")
	}
	return out, nil
}

type AdoptionObservation struct {
	Status     string `json:"status"`
	LastStatus string `json:"last_status,omitempty"`
	Evidence   string `json:"evidence"`
}

// ObserveAdoption polls only passive endpoints, verifying the selected MAC in managed site inventory.
func (c *Client) ObserveAdoption(ctx context.Context, siteID, selected string, wait time.Duration) (AdoptionObservation, error) {
	mac, err := net.ParseMAC(selected)
	if err != nil || len(mac) != 6 {
		return AdoptionObservation{}, errors.New("a single 48-bit device MAC address is required")
	}
	if wait < 0 || wait > 2*time.Minute {
		return AdoptionObservation{}, errors.New("wait must be between zero and two minutes")
	}
	if wait > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, wait)
		defer cancel()
	}
	last := AdoptionObservation{Status: "unknown"}
	selected = strings.ToUpper(dashMAC(mac.String()))
	for ctx.Err() == nil {
		obs, err := c.adoptionState(ctx, siteID, selected)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			return last, err
		}
		last = obs
		if wait == 0 || obs.Status == "verified_complete" || obs.Status == "failed" {
			return obs, nil
		}
		if sleepCtx(ctx, 2*time.Second) != nil {
			break
		}
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return AdoptionObservation{Status: "timed_out", LastStatus: last.Status, Evidence: "observation_deadline"}, nil
	}
	return last, ctx.Err()
}

func (c *Client) adoptionState(ctx context.Context, siteID, selected string) (AdoptionObservation, error) {
	managed, err := c.GetDevices(ctx, siteID)
	if err != nil {
		return AdoptionObservation{}, err
	}
	for _, d := range managed {
		if NormalizeMAC(d.MAC) == NormalizeMAC(selected) {
			return AdoptionObservation{"verified_complete", "", "selected_managed_site_inventory"}, nil
		}
	}
	page, err := c.PendingDevices(ctx, siteID, 1, 100, selected)
	if err != nil {
		return AdoptionObservation{}, err
	}
	result := AdoptionObservation{Status: "unknown", Evidence: "no_exact_pending_match"}
	for _, d := range page.Devices {
		if NormalizeMAC(d.MAC) != NormalizeMAC(selected) {
			continue
		}
		switch d.DetailStatus {
		case 22, 23:
			return AdoptionObservation{"started", "", "adopting_detail_status"}, nil
		case 24, 25:
			return AdoptionObservation{"failed", "", "failed_detail_status"}, nil
		case 20, 21:
			result = AdoptionObservation{"pending", "", "pending_detail_status"}
		default:
			result = AdoptionObservation{"unknown", "", "unclassified_detail_status"}
		}
		break
	}
	var readback struct {
		MAC  string `json:"deviceMac"`
		Code *int   `json:"adoptErrorCode"`
	}
	path := "sites/" + url.PathEscape(siteID) + "/devices/" + selected + "/adopt-result"
	if err := c.get(ctx, path, &readback); err != nil {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		result.Evidence += ";adopt_result_unavailable"
		return result, nil
	}
	if NormalizeMAC(readback.MAC) == NormalizeMAC(selected) && readback.Code != nil {
		switch *readback.Code {
		case -39002, -39003, -39004, -39005, -39329:
			return AdoptionObservation{"failed", "", "selected_adopt_error"}, nil
		case 0:
			return AdoptionObservation{"unverified", "", "adopt_success_awaiting_site_inventory"}, nil
		}
	}
	return result, nil
}
