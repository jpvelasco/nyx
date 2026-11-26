package omada

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/jpvelasco/nyx/internal/textsafe"
)

// WLANOptimizationRun is a row from the site planning-history collection.
// Time is the controller's epoch milliseconds for when the run happened;
// Mode is 0 for a scheduled run and 1 for a manual trigger.
type WLANOptimizationRun struct {
	ID          string `json:"planningHistroyId"`
	APCount     int    `json:"apNum"`
	Time        int64  `json:"time"`
	Mode        int    `json:"mode"`
	ScanSuccess bool   `json:"isScanSuccess"`
	MessageType int    `json:"msgType"`
	Message     string `json:"msg"`
	Failed2G    string `json:"failedMacs2g"`
	Failed5G    string `json:"failedMacs5g"`
	Failed6G    string `json:"failedMacs6g"`
}

// RFPlanningOccurrence describes when the scheduled optimization fires.
// TimingType 1 is daily; other values (e.g. weekly) are not modelled yet.
type RFPlanningOccurrence struct {
	TimingType int `json:"timingType"`
	Hour       int `json:"hour"`
	Minute     int `json:"minute"`
}

// RFPlanning is the site's scheduled WLAN optimization configuration.
type RFPlanning struct {
	ScheduleEnable bool                 `json:"scheduleEnable"`
	Occurrence     RFPlanningOccurrence `json:"occurrence"`
}

// GetRFPlanning reads the site's scheduled WLAN optimization configuration.
func (c *Client) GetRFPlanning(ctx context.Context, siteID string) (RFPlanning, error) {
	var planning RFPlanning
	if siteID == "" || siteID == "." || siteID == ".." {
		return planning, errors.New("invalid site id")
	}
	if err := c.get(ctx, "sites/"+url.PathEscape(siteID)+"/rfPlanning", &planning); err != nil {
		return planning, err
	}
	return planning, nil
}

// WLANOptimizationStatus describes the known controller status codes.
func WLANOptimizationStatus(code int) string {
	return wlanOptimizationStatuses[code]
}

var wlanOptimizationStatuses = map[int]string{
	7:      "No APs available for WLAN Optimization.",
	-34800: "No SSIDs are available on the band.",
	-34804: "No connected APs are available.",
	-34805: "No wired APs are available.",
	-34806: "No supported APs are available for WLAN optimization.",
	-34812: "WLAN optimization is not configured.",
	-34814: "WLAN optimization is already running.",
	-34823: "All 5 GHz channels are excluded.",
	-34825: "The optimization history entry was not found.",
}

// ListWLANOptimizationHistory reads all pages of the site's planning history.
func (c *Client) ListWLANOptimizationHistory(ctx context.Context, siteID string) ([]WLANOptimizationRun, error) {
	rows, _, err := fetchPaged[WLANOptimizationRun](ctx, c, planningHistoryPath(siteID), defaultPageSize)
	if err != nil {
		return nil, planningHistoryError(err)
	}
	return rows, nil
}

func planningHistoryPath(siteID string) string {
	return "sites/" + url.PathEscape(siteID) + "/planningHistory"
}

// Keep controller status codes and static guidance without echoing wire messages.
func planningHistoryError(err error) error {
	var apiErr *apiError
	if errors.As(err, &apiErr) {
		var message string
		switch {
		case WLANOptimizationStatus(apiErr.ErrorCode) != "":
			message = fmt.Sprintf("reading WLAN optimization history: controller error %d: %s", apiErr.ErrorCode, WLANOptimizationStatus(apiErr.ErrorCode))
		case apiErr.ErrorCode != 0:
			message = fmt.Sprintf("reading WLAN optimization history: controller error %d", apiErr.ErrorCode)
		case apiErr.StatusCode != 0:
			message = fmt.Sprintf("reading WLAN optimization history: HTTP %d", apiErr.StatusCode)
		}
		if message != "" {
			return &apiError{StatusCode: apiErr.StatusCode, ErrorCode: apiErr.ErrorCode, Msg: message}
		}
	}
	return errors.New("reading WLAN optimization history: transport or protocol error")
}

// WLANOptimizationDetail describes the recorded outcome for each AP.
type WLANOptimizationDetail struct {
	SuccessDevices int                  `json:"successDevices"`
	FailDevices    int                  `json:"failDevices"`
	Devices        []WLANOptimizationAP `json:"data"`
}

type WLANOptimizationAP struct {
	Name            string                 `json:"name"`
	IP              string                 `json:"ip"`
	Model           string                 `json:"model"`
	ModelVersion    string                 `json:"modelVersion"`
	FailMessage     string                 `json:"failMsg"`
	FailMessageType *int                   `json:"failMsgType"`
	TriggerReason   *int                   `json:"triggerReason"`
	Radio2G         *WLANOptimizationRadio `json:"radio2g"`
	Radio5G         *WLANOptimizationRadio `json:"radio5g"`
	Radio5G2        *WLANOptimizationRadio `json:"radio5g2"`
	Radio6G         *WLANOptimizationRadio `json:"radio6g"`
}

type WLANOptimizationRadio struct {
	ErrorCode       *int `json:"errCode"`
	LegacyErrorCode *int `json:"err_code"`
}

func (r *WLANOptimizationRadio) Code() *int {
	if r == nil {
		return nil
	}
	if r.ErrorCode != nil {
		return r.ErrorCode
	}
	return r.LegacyErrorCode
}

func (c *Client) GetWLANOptimizationHistory(ctx context.Context, siteID, historyID string) (WLANOptimizationDetail, error) {
	var detail WLANOptimizationDetail
	if historyID == "" || historyID == "." || historyID == ".." {
		return detail, errors.New("invalid WLAN optimization history ID")
	}
	if err := c.get(ctx, planningHistoryPath(siteID)+"/"+url.PathEscape(historyID), &detail); err != nil {
		return detail, planningHistoryError(err)
	}
	return detail, nil
}

func (ap WLANOptimizationAP) SafeFailureMessage() string {
	text := ap.FailMessage
	for _, value := range []string{ap.Name, ap.IP, ap.Model, ap.ModelVersion} {
		if value != "" {
			text = strings.ReplaceAll(text, value, "[device]")
		}
	}
	return textsafe.Message(text)
}
