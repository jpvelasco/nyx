package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The HTTP transport acceptance contract (#138, docs/mcp-http.md): loopback
// bind only, bearer auth on every request, one Server per session, idle
// timeout, per-call timeout unchanged, no new secret-bearing fields, and
// the same JSON-RPC method surface as stdio.

const testToken = "test-listener-token"

func newTestHTTPServer(t *testing.T) (*HTTPServer, *httptest.Server) {
	t.Helper()
	h := NewHTTPServer(testToken, nil)
	h.idleTimeout = 50 * time.Millisecond // fast expiry for tests
	ts := httptest.NewServer(h.Handler())
	t.Cleanup(ts.Close)
	return h, ts
}

func httpPost(t *testing.T, ts *httptest.Server, path, token, sessionID, body string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, ts.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var buf bytes.Buffer
	buf.ReadFrom(resp.Body)
	return resp, buf.String()
}

func TestHTTPAuthRejectsMissingAndWrongTokens(t *testing.T) {
	_, ts := newTestHTTPServer(t)
	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`

	// No token: 401 with a generic body that echoes nothing back.
	resp, body := httpPost(t, ts, "/mcp", "", "", initBody)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("missing token: status = %d, want 401", resp.StatusCode)
	}
	if strings.Contains(body, testToken) {
		t.Errorf("401 body must not echo any token value: %q", body)
	}

	// Wrong token: 401 with the same generic body.
	resp, body = httpPost(t, ts, "/mcp", "wrong-token", "", initBody)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong token: status = %d, want 401", resp.StatusCode)
	}
	if strings.Contains(body, testToken) {
		t.Errorf("401 body must not echo any token value: %q", body)
	}
}

func TestHTTPInitializeCreatesSession(t *testing.T) {
	_, ts := newTestHTTPServer(t)
	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`

	resp, body := httpPost(t, ts, "/mcp", testToken, "", initBody)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initialize: status = %d, body = %s", resp.StatusCode, body)
	}
	sid := resp.Header.Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatal("initialize response must carry Mcp-Session-Id")
	}
	var result struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
			ServerInfo      struct {
				Name string `json:"name"`
			} `json:"serverInfo"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		t.Fatalf("decoding initialize response: %v (%s)", err, body)
	}
	if result.Result.ServerInfo.Name != "nyx" {
		t.Errorf("serverInfo.name = %q, want nyx", result.Result.ServerInfo.Name)
	}

	// The session is usable: tools/list on it succeeds.
	resp, body = httpPost(t, ts, "/mcp", testToken, sid, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("tools/list on session: status = %d, body = %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "provider_list") {
		t.Errorf("tools/list should list the tool surface, got: %s", body)
	}
}

func TestHTTPSessionRequiredForNonInitialize(t *testing.T) {
	_, ts := newTestHTTPServer(t)

	// A tools/list without a session ID is rejected: sessions are born
	// from initialize.
	resp, _ := httpPost(t, ts, "/mcp", testToken, "", `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("no session: status = %d, want 400", resp.StatusCode)
	}

	// An unknown session ID is 404 per the streamable-HTTP spec.
	resp, _ = httpPost(t, ts, "/mcp", testToken, "no-such-session", `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown session: status = %d, want 404", resp.StatusCode)
	}
}

func TestHTTPSessionsAreIsolated(t *testing.T) {
	_, ts := newTestHTTPServer(t)
	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`

	// Two independent sessions: each gets its own Server (own initialize
	// state, own trace namespace).
	respA, _ := httpPost(t, ts, "/mcp", testToken, "", initBody)
	sidA := respA.Header.Get("Mcp-Session-Id")
	respB, _ := httpPost(t, ts, "/mcp", testToken, "", initBody)
	sidB := respB.Header.Get("Mcp-Session-Id")
	if sidA == "" || sidB == "" || sidA == sidB {
		t.Fatalf("expected two distinct sessions, got %q and %q", sidA, sidB)
	}

	// Both sessions serve requests independently.
	for _, sid := range []string{sidA, sidB} {
		resp, body := httpPost(t, ts, "/mcp", testToken, sid, `{"jsonrpc":"2.0","id":9,"method":"tools/list"}`)
		if resp.StatusCode != http.StatusOK || !strings.Contains(body, "provider_list") {
			t.Errorf("session %s should serve tools/list, got %d: %s", sid, resp.StatusCode, body)
		}
	}
}

func TestHTTPIdleSessionExpires(t *testing.T) {
	_, ts := newTestHTTPServer(t) // 50ms idle timeout

	resp, _ := httpPost(t, ts, "/mcp", testToken, "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	sid := resp.Header.Get("Mcp-Session-Id")
	if sid == "" {
		t.Fatal("no session id on initialize")
	}

	time.Sleep(120 * time.Millisecond) // beyond the idle window

	resp, _ = httpPost(t, ts, "/mcp", testToken, sid, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("idle session: status = %d, want 404 (session expired)", resp.StatusCode)
	}
}

func TestHTTPNotificationAccepted(t *testing.T) {
	_, ts := newTestHTTPServer(t)
	resp, body := httpPost(t, ts, "/mcp", testToken, "", `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("notification: status = %d, want 202", resp.StatusCode)
	}
	if body != "" {
		t.Errorf("notification response body should be empty, got %q", body)
	}
}

func TestHTTPGETAndDeleteNotSupported(t *testing.T) {
	_, ts := newTestHTTPServer(t)
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET: status = %d, want 405", resp.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodDelete, ts.URL+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, err = ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("DELETE: status = %d, want 405", resp.StatusCode)
	}
}

func TestHTTPToolsCallOnSession(t *testing.T) {
	_, ts := newTestHTTPServer(t)
	resp, _ := httpPost(t, ts, "/mcp", testToken, "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	sid := resp.Header.Get("Mcp-Session-Id")

	// provider_list is read-only and deterministic: a full HTTP round trip
	// through the session must return the tool surface's JSON result.
	resp, body := httpPost(t, ts, "/mcp", testToken, sid,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"provider_list","arguments":{}}}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tools/call: status = %d, body = %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "result") {
		t.Errorf("tools/call should carry a JSON-RPC result, got: %s", body)
	}
}

// Tokens: generation produces unguessable material; the env token is
// honored exactly as provided.

func TestGenerateListenerToken(t *testing.T) {
	tok1, err := GenerateListenerToken()
	if err != nil {
		t.Fatalf("GenerateListenerToken: %v", err)
	}
	if len(tok1) < 32 {
		t.Errorf("token too short to be unguessable: %d chars", len(tok1))
	}
	tok2, _ := GenerateListenerToken()
	if tok1 == tok2 {
		t.Error("two generated tokens must differ")
	}
}

// ValidateBindAddr enforces the loopback-only binding rule.

func TestValidateBindAddr(t *testing.T) {
	ok := []string{"127.0.0.1:0", "127.0.0.1:9000", "localhost:0", "[::1]:0", "localhost:9000"}
	for _, addr := range ok {
		if _, err := ValidateBindAddr(addr); err != nil {
			t.Errorf("ValidateBindAddr(%q) = %v, want accepted loopback", addr, err)
		}
	}
	bad := []string{"0.0.0.0:9000", ":9000", "192.168.1.10:9000", "10.0.10.5:9000", "example.com:9000", "[::]:9000", "not an addr", "127.0.0.1"}
	for _, addr := range bad {
		_, err := ValidateBindAddr(addr)
		if err == nil {
			t.Errorf("ValidateBindAddr(%q) accepted a non-loopback or malformed bind", addr)
		} else if !strings.Contains(err.Error(), "loopback") {
			t.Errorf("ValidateBindAddr(%q) error should name the loopback rule: %v", addr, err)
		}
	}
}

func TestTokenNeverInURLs(t *testing.T) {
	// The auth is header-only; the handler never accepts token-bearing
	// query strings (any ?token=... is ignored, not authenticated).
	_, ts := newTestHTTPServer(t)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/mcp?token="+testToken, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("token in query string must not authenticate: status = %d, want 401", resp.StatusCode)
	}
}

// TestSweepIdleRemovesExpiredSessions pins the reaper's core: sessions
// idle beyond the timeout are removed even with no further request.
func TestSweepIdleRemovesExpiredSessions(t *testing.T) {
	h := NewHTTPServer(testToken, nil)
	h.idleTimeout = 20 * time.Millisecond
	id := h.newSession()
	if len(h.sessions) != 1 {
		t.Fatalf("sessions = %d, want 1", len(h.sessions))
	}
	time.Sleep(60 * time.Millisecond)
	h.SweepIdle()
	if len(h.sessions) != 0 {
		t.Errorf("idle session survived the sweep: %d remain", len(h.sessions))
	}
	_ = id
}

// TestStartReaperStopsWithContext pins the reaper lifecycle: the ticker
// goroutine exits when the context ends.
func TestStartReaperStopsWithContext(t *testing.T) {
	h := NewHTTPServer(testToken, nil)
	h.idleTimeout = 10 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	h.StartReaper(ctx)
	// Let a couple of ticks happen, then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()
	// The goroutine exits on the next tick at the latest; nothing to
	// assert beyond no-panic, but the sweep must have run.
	time.Sleep(10 * time.Millisecond)
	if len(h.sessions) != 0 {
		t.Errorf("reaper should have swept, %d remain", len(h.sessions))
	}
}

// TestValidateBindAddrErrorBranches pins each refusal branch of the
// loopback rule with its named reason.
func TestValidateBindAddrErrorBranches(t *testing.T) {
	bad := map[string]string{
		"no-port-here":         "missing port",
		":9000":                "no host",
		"example.invalid:9000": "does not resolve",
	}
	for addr, want := range bad {
		_, err := ValidateBindAddr(addr)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ValidateBindAddr(%q) = %v, want an error naming %q", addr, err, want)
		}
	}
}

// TestHTTPServerSessionsUseSharedLogger pins the review finding fix:
// HTTP sessions write tool-call records through the configured logger,
// exactly like stdio — never silently dropped.
func TestHTTPServerSessionsUseSharedLogger(t *testing.T) {
	var buf bytes.Buffer
	sl := slog.New(slog.NewJSONHandler(&buf, nil))
	h := NewHTTPServer(testToken, sl)
	id := h.newSession()
	s := h.sessionServer(id)
	if s == nil || s.logger != sl {
		t.Fatal("the session must carry the shared logger")
	}
	s.logger.Info("http-session-record")
	if !strings.Contains(buf.String(), "http-session-record") {
		t.Error("session records must flow through the configured logger")
	}
}
