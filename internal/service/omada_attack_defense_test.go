package service

import (
	"net/http"
	"strings"
	"testing"
)

func omadaAttackDefenseHandler(t *testing.T, failClientStatus bool) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		case "/openapi/v1/abc123/sites/s1/attack-defense":
			writeOmadaEnvelope(w, 0, `{"tcpScanEnable":true,"tcpScanReject":true,"largePingEnable":false,"icmpTimestampRequestReject":true}`)
		case "/openapi/v1/abc123/sites/s1/clients/aa-bb-cc-dd-ee-01":
			if failClientStatus {
				writeOmadaEnvelope(w, -1, `null`)
				return
			}
			writeOmadaEnvelope(w, 0, `{"blocked":true}`)
		case "/openapi/v1/abc123/sites/s1/clients/aa-bb-cc-dd-ee-02/unblock":
			writeOmadaEnvelope(w, 0, `{}`)
		default:
			http.NotFound(w, r)
		}
	}
}

func TestOmadaServiceAttackDefense(t *testing.T) {
	ts := omadaTestServer(t, omadaAttackDefenseHandler(t, false))
	opts := OmadaOptions{Host: ts.URL, ClientID: "a", ClientSecret: "b", SkipTLSVerify: true}
	svc := NewOmadaService()
	ctx := t.Context()

	report, err := svc.AttackDefense(ctx, opts, "aa:bb:cc:dd:ee:01")
	if err != nil {
		t.Fatalf("AttackDefense: %v", err)
	}
	if report.Settings.TCPScanReject == nil || !*report.Settings.TCPScanReject || report.Settings.LargePingEnabled == nil || *report.Settings.LargePingEnabled {
		t.Errorf("settings = %+v", report.Settings)
	}
	if report.ClientBlocked == nil || !*report.ClientBlocked {
		t.Errorf("ClientBlocked = %v, want true", report.ClientBlocked)
	}
	if report.GatewayRuntime != "device_side_unobservable" || report.Guidance == "" {
		t.Errorf("runtime = %q guidance = %q", report.GatewayRuntime, report.Guidance)
	}

	noMac, err := svc.AttackDefense(ctx, opts, "")
	if err != nil {
		t.Fatalf("AttackDefense without mac: %v", err)
	}
	if noMac.ClientBlocked != nil {
		t.Errorf("ClientBlocked = %v, want nil without a client", noMac.ClientBlocked)
	}

	if err := svc.UnblockClient(ctx, opts, "aa:bb:cc:dd:ee:02"); err != nil {
		t.Fatalf("UnblockClient: %v", err)
	}
	if err := svc.UnblockClient(ctx, opts, "not-a-mac"); err == nil || !strings.Contains(err.Error(), "48-bit MAC") {
		t.Fatalf("UnblockClient invalid mac = %v, want 48-bit MAC error", err)
	}
}

func TestOmadaServiceAttackDefense_Errors(t *testing.T) {
	ts := omadaTestServer(t, omadaAttackDefenseHandler(t, true))
	opts := OmadaOptions{Host: ts.URL, ClientID: "a", ClientSecret: "b", SkipTLSVerify: true}
	svc := NewOmadaService()
	ctx := t.Context()

	// settings succeeds, the client status read fails: the error must surface
	_, err := svc.AttackDefense(ctx, opts, "aa:bb:cc:dd:ee:01")
	if err == nil || !strings.Contains(err.Error(), "reading client block status") {
		t.Fatalf("AttackDefense = %v, want client block status failure", err)
	}
	// unblock for a client the fixture does not model must surface the controller error
	if err := svc.UnblockClient(ctx, opts, "aa:bb:cc:dd:ee:03"); err == nil || !strings.Contains(err.Error(), "unblocking controller client") {
		t.Fatalf("UnblockClient = %v, want controller error wrap", err)
	}

	down := omadaTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/openapi/authorize/token":
			writeOmadaEnvelope(w, 0, `{"accessToken":"tok"}`)
		case "/openapi/v1/abc123/sites":
			writeOmadaEnvelope(w, 0, `{"totalRows":1,"data":[{"id":"s1","name":"HQ"}]}`)
		default:
			writeOmadaEnvelope(w, -1, `null`)
		}
	})
	if _, err := NewOmadaService().AttackDefense(ctx, OmadaOptions{Host: down.URL, ClientID: "a", ClientSecret: "b", SkipTLSVerify: true}, ""); err == nil {
		t.Fatal("expected settings fetch error")
	}
}
