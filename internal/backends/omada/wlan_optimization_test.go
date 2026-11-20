package omada

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type wlanTestTransport func(*http.Request) (*http.Response, error)

func (f wlanTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestWLANOptimizationReads(t *testing.T) {
	c := &Client{host: "controller.example", omadaCID: "controller", token: "test-token"}
	c.httpClient = &http.Client{Transport: wlanTestTransport(func(r *http.Request) (*http.Response, error) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s", r.Method)
		}
		var body string
		switch r.URL.RequestURI() {
		case "/openapi/v1/controller/sites/site/planningHistory?page=1&pageSize=200":
			body = `{"errorCode":0,"result":{"totalRows":2,"data":[{"planningHistroyId":"run-one","apNum":0,"isScanSuccess":false,"msgType":-34806,"failedMacs2g":"00-00-00-00-00-01","time":1763446618000,"mode":0}]}}`
		case "/openapi/v1/controller/sites/site/planningHistory?page=2&pageSize=200":
			body = `{"errorCode":0,"result":{"data":[{"planningHistroyId":"run-two","apNum":1,"isScanSuccess":true}]}}`
		case "/openapi/v1/controller/sites/site/planningHistory/run-one":
			body = `{"errorCode":0,"result":{"data":[]}}`
		case "/openapi/v1/controller/sites/site/planningHistory/run-two":
			body = `{"errorCode":0,"result":{"failDevices":1,"data":[{"name":"fixture-ap","failMsg":"No scan result for fixture-ap","failMsgType":0,"triggerReason":2,"radio2g":{"errCode":0},"radio5g":{"err_code":-34815}}]}}`
		case "/openapi/v1/controller/sites/site/planningHistory/missing":
			body = `{"errorCode":-34825,"msg":"raw controller detail"}`
		default:
			t.Fatalf("unexpected request %s", r.URL.RequestURI())
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	rows, err := c.ListWLANOptimizationHistory(t.Context(), "site")
	if err != nil || len(rows) != 2 || rows[0].MessageType != -34806 || rows[0].ID != "run-one" || !rows[1].ScanSuccess {
		t.Fatalf("history=%+v err=%v", rows, err)
	}
	if rows[0].Time != 1763446618000 || rows[0].Mode != 0 {
		t.Fatalf("run-one time/mode = %d/%d", rows[0].Time, rows[0].Mode)
	}
	empty, err := c.GetWLANOptimizationHistory(t.Context(), "site", "run-one")
	if err != nil || len(empty.Devices) != 0 {
		t.Fatalf("empty detail=%+v err=%v", empty, err)
	}
	detail, err := c.GetWLANOptimizationHistory(t.Context(), "site", "run-two")
	if err != nil || len(detail.Devices) != 1 || detail.FailDevices != 1 {
		t.Fatalf("detail=%+v err=%v", detail, err)
	}
	ap := detail.Devices[0]
	if ap.SafeFailureMessage() != "No scan result for [device]" || *ap.FailMessageType != 0 || *ap.TriggerReason != 2 || *ap.Radio2G.Code() != 0 || *ap.Radio5G.Code() != -34815 || ap.Radio6G.Code() != nil {
		t.Fatalf("unexpected AP diagnostic %+v", ap)
	}
	_, err = c.GetWLANOptimizationHistory(t.Context(), "site", "missing")
	if err == nil || !strings.Contains(err.Error(), "-34825") || strings.Contains(err.Error(), "raw controller detail") {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestGetRFPlanning(t *testing.T) {
	newClient := func(date string) *Client {
		c := &Client{host: "controller.example", omadaCID: "controller", token: "test-token"}
		c.httpClient = &http.Client{Transport: wlanTestTransport(func(r *http.Request) (*http.Response, error) {
			if r.Method != http.MethodGet || r.URL.RequestURI() != "/openapi/v1/controller/sites/site/rfPlanning" {
				t.Fatalf("unexpected request %s %s", r.Method, r.URL.RequestURI())
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Date": []string{date}},
				Body:       io.NopCloser(strings.NewReader(`{"errorCode":0,"result":{"scheduleEnable":true,"occurrence":{"timingType":1,"hour":10,"minute":0}}}`)),
			}, nil
		})}
		return c
	}
	// The Date header is the controller's own wall clock; schedule math
	// uses it so local/controller clock drift cancels out. The first value
	// is the format a live controller sends.
	for _, tc := range []struct {
		date string
		want string // empty means the clock must stay unknown
	}{
		{"Thu, 19 Nov 2026 09:30:00 GMT", "2026-11-19T09:30:00Z"},
		{"Thu, 19 Nov 2026 09:30:00 +0000", "2026-11-19T09:30:00Z"},
		{"not a date", ""},
	} {
		c := newClient(tc.date)
		planning, err := c.GetRFPlanning(t.Context(), "site")
		if err != nil || !planning.ScheduleEnable || planning.Occurrence.TimingType != 1 || planning.Occurrence.Hour != 10 || planning.Occurrence.Minute != 0 {
			t.Fatalf("date %q: planning=%+v err=%v", tc.date, planning, err)
		}
		got := c.ControllerNow()
		if tc.want == "" {
			if !got.IsZero() {
				t.Fatalf("date %q: controller now = %v, want zero", tc.date, got)
			}
			continue
		}
		if got.UTC().Format(time.RFC3339) != tc.want {
			t.Fatalf("date %q: controller now = %v, want %s", tc.date, got, tc.want)
		}
	}
	if _, err := newClient("Thu, 19 Nov 2026 09:30:00 GMT").GetRFPlanning(t.Context(), ".."); err == nil {
		t.Fatal("expected invalid site id error")
	}
}

func TestWLANOptimizationErrors(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{&apiError{ErrorCode: -123, Msg: "raw details"}, "controller error -123"},
		{&apiError{StatusCode: 502}, "HTTP 502"},
		{io.ErrUnexpectedEOF, "transport or protocol error"},
	} {
		got := planningHistoryError(tc.err).Error()
		if !strings.Contains(got, tc.want) || strings.Contains(got, "raw details") {
			t.Errorf("error=%q want %q", got, tc.want)
		}
	}
	c := &Client{}
	if _, err := c.GetWLANOptimizationHistory(t.Context(), "site", ".."); err == nil {
		t.Fatal("expected invalid ID error")
	}
}

func TestSafeFailureMessageSpacesEscapes(t *testing.T) {
	ap := WLANOptimizationAP{Name: "ap-lobby", FailMessage: "scan\x1b[2Jfailed on\u202eap-lobby\n"}
	if got := ap.SafeFailureMessage(); got != "scan [2Jfailed on [device]" {
		t.Errorf("SafeFailureMessage = %q", got)
	}
}
