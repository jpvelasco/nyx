package omada

import (
	"io"
	"net/http"
	"strings"
	"testing"
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
			body = `{"errorCode":0,"result":{"totalRows":2,"data":[{"planningHistroyId":"run-one","apNum":0,"isScanSuccess":false,"msgType":-34806,"failedMacs2g":"00-00-00-00-00-01"}]}}`
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
