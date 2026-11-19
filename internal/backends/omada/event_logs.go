package omada

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type EventLogQuery struct {
	Module    string
	TimeStart string
	TimeEnd   string
	Since     string
	Page      int
	PageSize  int
}

type EventLog struct {
	ID      string `json:"id"`
	Key     string `json:"key"`
	Module  string `json:"module"`
	Content string `json:"content"`
	Time    int64  `json:"time"`
}

type EventLogPage struct {
	TotalRows   int        `json:"totalRows"`
	CurrentPage int        `json:"currentPage"`
	CurrentSize int        `json:"currentSize"`
	Data        []EventLog `json:"data"`
}

// GetEventLogs reads one page of event history using the published site endpoint.
func (c *Client) GetEventLogs(ctx context.Context, siteID string, query EventLogQuery) (EventLogPage, error) {
	var page EventLogPage
	params, err := query.values(time.Now())
	if err != nil {
		return page, err
	}
	err = c.get(ctx, "sites/"+url.PathEscape(siteID)+"/logs/events?"+params.Encode(), &page)
	return page, err
}

func (q EventLogQuery) values(now time.Time) (url.Values, error) {
	if q.Page == 0 {
		q.Page = 1
	}
	if q.PageSize == 0 {
		q.PageSize = 50
	}
	if q.Page < 1 || q.PageSize < 1 || q.PageSize > 1000 {
		return nil, fmt.Errorf("page must be positive and page size must be between 1 and 1000")
	}
	end := now
	if q.TimeEnd != "" {
		var err error
		end, err = time.Parse(time.RFC3339, q.TimeEnd)
		if err != nil {
			return nil, fmt.Errorf("time_end must be an RFC3339 timestamp")
		}
	}
	if q.TimeStart != "" && q.Since != "" {
		return nil, fmt.Errorf("specify time_start or since, not both")
	}
	start := end.Add(-24 * time.Hour)
	switch {
	case q.TimeStart != "":
		var err error
		start, err = time.Parse(time.RFC3339, q.TimeStart)
		if err != nil {
			return nil, fmt.Errorf("time_start must be an RFC3339 timestamp")
		}
	case q.Since != "":
		duration, err := eventLogDuration(q.Since)
		if err != nil {
			return nil, err
		}
		start = end.Add(-duration)
	}
	if start.UnixMilli() >= end.UnixMilli() {
		return nil, fmt.Errorf("time_start must precede time_end by at least one millisecond")
	}
	params := url.Values{
		"page": {strconv.Itoa(q.Page)}, "pageSize": {strconv.Itoa(q.PageSize)},
		"filters.timeStart": {strconv.FormatInt(start.UnixMilli(), 10)}, "filters.timeEnd": {strconv.FormatInt(end.UnixMilli(), 10)},
	}
	switch q.Module {
	case "System", "Device", "Client":
		params.Set("filters.module", q.Module)
	case "":
	default:
		return nil, fmt.Errorf("module must be System, Device, or Client")
	}
	return params, nil
}

func eventLogDuration(value string) (time.Duration, error) {
	if days, ok := strings.CutSuffix(value, "d"); ok {
		value = days + "h"
		duration, err := time.ParseDuration(value)
		if err == nil && duration > 0 && duration <= (1<<63-1)/24 {
			return duration * 24, nil
		}
	} else if duration, err := time.ParseDuration(value); err == nil && duration > 0 {
		return duration, nil
	}
	return 0, fmt.Errorf("since must be a positive duration such as 24h or 30d")
}
