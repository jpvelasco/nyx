package omada

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

func TestExportLogs(t *testing.T) {
	var (
		mu      sync.Mutex
		method  string
		body    map[string]any
		headers http.Header
	)
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path != "/openapi/v1/abc123/logs/export" {
			t.Errorf("path = %s, want /openapi/v1/abc123/logs/export", r.URL.Path)
		}
		method = r.Method
		body = map[string]any{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		headers = r.Header.Clone()
		w.Header().Set("Content-Type", "application/zip;charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=LogList_1763532000000.zip")
		io.WriteString(w, "PK\x03\x04")
	})
	got, err := c.ExportLogs(context.Background(), []string{"s1"}, LogExportCSV)
	if err != nil {
		t.Fatalf("ExportLogs: %v", err)
	}
	if got.Filename != "LogList_1763532000000.zip" || string(got.Data) != "PK\x03\x04" {
		t.Errorf("export = %q %q, want filename and raw bytes", got.Filename, got.Data)
	}
	mu.Lock()
	defer mu.Unlock()
	if method != http.MethodPost {
		t.Errorf("method = %s, want POST (the export endpoint is POST-only)", method)
	}
	if body["format"] != float64(LogExportCSV) {
		t.Errorf("format = %v, want %d", body["format"], LogExportCSV)
	}
	sites, _ := body["siteIds"].([]any)
	if len(sites) != 1 || sites[0] != "s1" {
		t.Errorf("siteIds = %v, want [s1]", body["siteIds"])
	}
	if headers.Get("Content-Type") != "application/json" {
		t.Errorf("request Content-Type = %q, want application/json", headers.Get("Content-Type"))
	}
}

func TestExportLogsValidation(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		t.Errorf("no request should reach the controller")
	})
	cases := []struct {
		name   string
		sites  []string
		format int
		want   string
	}{
		{"no sites", nil, LogExportCSV, "at least one site id"},
		{"bad format", []string{"s1"}, 7, "format must be"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.ExportLogs(context.Background(), tc.sites, tc.format)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want contains %q", err, tc.want)
			}
		})
	}
}

func TestExportLogsEnvelopeErrors(t *testing.T) {
	cases := []struct {
		name      string
		errorCode int
		want      string
	}{
		{"unsupported path", -1600, "unsupported request path"},
		{"export disabled", -1, "operation failed"},
		{"missing params", -1001, "controller error -1001"},
		{"forbidden", -1005, "operation forbidden"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/openapi/v1/abc123/logs/export" {
					t.Errorf("path = %s, want logs/export", r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				writeEnvelope(w, tc.errorCode, "boom", "null")
			})
			_, err := c.ExportLogs(context.Background(), []string{"s1"}, LogExportCSV)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %v, want contains %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), "log export failed") {
				t.Errorf("error = %v, want the log export operation named", err)
			}
		})
	}
}

// An expired token on the export path must trigger the single automatic
// re-mint and then succeed with the fresh token.
func TestExportLogsReauth(t *testing.T) {
	var (
		mu      sync.Mutex
		mintN   int
		exportN int
	)
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/openapi/authorize/token":
			mintN++
			writeEnvelope(w, 0, "", `{"accessToken":"AT-2"}`)
		case "/openapi/v1/abc123/logs/export":
			exportN++
			if exportN == 1 {
				writeEnvelope(w, -44112, "token expired", "null")
				return
			}
			w.Header().Set("Content-Type", "application/zip")
			w.Header().Set("Content-Disposition", `attachment; filename="LogList_2.zip"`)
			io.WriteString(w, "PK")
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})
	if err := c.Login(context.Background(), "cid", "sec"); err != nil {
		t.Fatalf("Login: %v", err)
	}
	got, err := c.ExportLogs(context.Background(), []string{"s1"}, LogExportCSV)
	if err != nil {
		t.Fatalf("ExportLogs: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if mintN != 2 {
		t.Errorf("mint calls = %d, want 2 (initial mint plus one re-mint)", mintN)
	}
	if exportN != 2 {
		t.Errorf("export calls = %d, want 2 (expired attempt plus retry)", exportN)
	}
	if got.Filename != "LogList_2.zip" {
		t.Errorf("filename = %q, want LogList_2.zip", got.Filename)
	}
}

// A transient 5xx is retried with backoff; the first failure must not
// surface when a retry succeeds.
func TestExportLogsRetriesTransient(t *testing.T) {
	var (
		mu sync.Mutex
		n  int
	)
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		n++
		attempt := n
		mu.Unlock()
		if attempt == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		w.Header().Set("Content-Disposition", "attachment; filename=LogList_3.zip")
		io.WriteString(w, "PK")
	})
	got, err := c.ExportLogs(context.Background(), []string{"s1"}, LogExportXLSX)
	if err != nil {
		t.Fatalf("ExportLogs: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if n != 2 {
		t.Errorf("attempts = %d, want 2 (one 5xx plus one retry)", n)
	}
	if got.Filename != "LogList_3.zip" {
		t.Errorf("filename = %q, want LogList_3.zip", got.Filename)
	}
}

func TestExportLogsTransientExhausted(t *testing.T) {
	var (
		mu sync.Mutex
		n  int
	)
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		n++
		mu.Unlock()
		w.WriteHeader(http.StatusBadGateway)
	})
	_, err := c.ExportLogs(context.Background(), []string{"s1"}, LogExportCSV)
	if err == nil || !strings.Contains(err.Error(), "HTTP 502") {
		t.Fatalf("error = %v, want the HTTP 502 surfaced", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if n != c.maxRetries+1 {
		t.Errorf("attempts = %d, want %d (initial plus max retries)", n, c.maxRetries+1)
	}
}

// A JSON envelope with errorCode 0 is not a valid export success: the
// contract is a binary attachment, so the download must fail closed.
func TestExportLogsJSONSuccessFailsClosed(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		writeEnvelope(w, 0, "", `{"result":true}`)
	})
	_, err := c.ExportLogs(context.Background(), []string{"s1"}, LogExportCSV)
	if err == nil || !strings.Contains(err.Error(), "JSON response instead of a log export attachment") {
		t.Fatalf("error = %v, want the JSON-success fail-closed message", err)
	}
}

func TestAttachmentFilename(t *testing.T) {
	cases := map[string]string{
		"attachment; filename=LogList_1763532000000.zip":   "LogList_1763532000000.zip",
		`attachment; filename="LogList_1763532000000.zip"`: "LogList_1763532000000.zip",
		"attachment":                            "",
		"":                                      "",
		"attachment; filename=..%2F..%2Fpasswd": "..%2F..%2Fpasswd",
		"attachment; filename=../../etc/passwd": "", // unparseable token
		"attachment; filename=C:\\logs\\LogList.zip": "", // unparseable token
		"inline": "",
	}
	for in, want := range cases {
		if got := attachmentFilename(in); got != want {
			t.Errorf("attachmentFilename(%q) = %q, want %q", in, got, want)
		}
	}
}
