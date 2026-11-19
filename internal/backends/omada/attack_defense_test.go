package omada

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type defenseTransport func(*http.Request) (*http.Response, error)

func (f defenseTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAttackDefenseRoutes(t *testing.T) {
	c := &Client{host: "controller.example", omadaCID: "controller", token: "fixture"}
	calls := 0
	const prefix = "/openapi/v1/controller/sites/site/"
	c.httpClient = &http.Client{Transport: defenseTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		var body string
		status := http.StatusOK
		switch r.Method + " " + strings.TrimPrefix(r.URL.Path, prefix) {
		case "GET attack-defense":
			body = `{"errorCode":0,"result":{"tcpScanReject":true,"largePingEnable":false}}`
		case "GET clients/00-00-00-00-00-01":
			body = `{"errorCode":0,"result":{"blocked":false}}`
		case "POST clients/00-00-00-00-00-01/unblock":
			body = `{"errorCode":0,"msg":""}`
		case "POST clients/00-00-00-00-00-02/unblock":
			status = http.StatusBadGateway
		default:
			t.Fatalf("unexpected endpoint %s %s", r.Method, r.URL.Path)
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body))}, nil
	})}
	cfg, err := c.GetAttackDefenseSettings(t.Context(), "site")
	if err != nil || cfg.TCPScanReject == nil || !*cfg.TCPScanReject || cfg.LargePingEnabled == nil || *cfg.LargePingEnabled {
		t.Fatalf("cfg=%+v err=%v", cfg, err)
	}
	blocked, err := c.ClientBlockStatus(t.Context(), "site", "00:00:00:00:00:01")
	if err != nil || blocked == nil || *blocked {
		t.Fatalf("blocked=%v err=%v", blocked, err)
	}
	if err = c.UnblockClient(t.Context(), "site", "00:00:00:00:00:01"); err != nil {
		t.Fatal(err)
	}
	if err = c.UnblockClient(t.Context(), "site", "00:00:00:00:00:02"); err == nil || !strings.Contains(err.Error(), "HTTP 502") {
		t.Fatalf("unexpected error %v", err)
	}
	if err = c.UnblockClient(t.Context(), "site", "../all"); err == nil || calls != 4 {
		t.Fatalf("invalid selector or retried failed POST: calls=%d err=%v", calls, err)
	}
}

func TestAttackDefenseErrorPreservesSafeDetails(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{context.Canceled, "context canceled"},
		{&apiError{ErrorCode: -1005, Msg: "raw details"}, "controller error -1005"},
		{io.ErrUnexpectedEOF, "transport or protocol error"},
	} {
		err := attackDefenseError("reading settings", tc.err)
		if !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "raw details") {
			t.Errorf("error=%q want %q", err, tc.want)
		}
	}
}
