package omada

import (
	"net/http"
	"strings"
	"testing"
)

func TestGetEventLogs(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/openapi/v1/abc123/sites/s1/logs/events" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		for k, want := range map[string]string{"page": "2", "pageSize": "10", "filters.module": "Device", "filters.timeStart": "1764547200000", "filters.timeEnd": "1767139200000"} {
			if got := r.URL.Query().Get(k); got != want {
				t.Errorf("%s = %q, want %q", k, got, want)
			}
		}
		writeEnvelope(w, 0, "", `{"totalRows":11,"currentPage":2,"currentSize":1,"data":[{"id":"event-1","key":"optimization","module":"Device","content":"Optimization completed","time":1767139100000}]}`)
	})
	page, err := c.GetEventLogs(t.Context(), "s1", EventLogQuery{Page: 2, PageSize: 10, Module: "Device", Since: "30d", TimeEnd: "2025-12-31T00:00:00Z"})
	if err != nil || page.TotalRows != 11 || page.CurrentPage != 2 || len(page.Data) != 1 || page.Data[0].Key != "optimization" {
		t.Fatalf("page=%+v err=%v", page, err)
	}
}

func TestGetEventLogsErrors(t *testing.T) {
	c, _ := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		writeEnvelope(w, -1600, "Unsupported request path", `null`)
	})
	for _, tc := range []struct {
		query EventLogQuery
		want  string
	}{
		{EventLogQuery{}, "Unsupported request path"},
		{EventLogQuery{Module: "Unknown"}, "module must be"},
		{EventLogQuery{PageSize: 1001}, "page size must be"},
		{EventLogQuery{TimeStart: "yesterday"}, "time_start must be"},
		{EventLogQuery{TimeEnd: "tomorrow"}, "time_end must be"},
		{EventLogQuery{Since: "0h"}, "since must be"},
		{EventLogQuery{TimeStart: "2025-12-31T00:00:00Z", Since: "2h"}, "specify time_start or since"},
		{EventLogQuery{TimeStart: "2025-12-31T00:00:00Z", TimeEnd: "2025-12-31T00:00:00Z"}, "must precede"},
	} {
		_, err := c.GetEventLogs(t.Context(), "s1", tc.query)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("query %+v: error=%v, want %q", tc.query, err, tc.want)
		}
	}
}
