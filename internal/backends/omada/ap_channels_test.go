package omada

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestGetAPChannels(t *testing.T) {
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method %s", r.Method)
		}
		switch r.URL.Path {
		case "/openapi/v1/abc123/sites/s1/networks/devices":
			writeEnvelope(w, 0, "", `[{"name":"gateway","type":"gateway"},{"name":"AP-01","type":"AP","mac":"AA-BB-CC-DD-EE-01"}]`)
		case "/openapi/v1/abc123/sites/s1/aps/aa-bb-cc-dd-ee-01/radios":
			writeEnvelope(w, 0, "", `{"wp2g":{"actualChannel":"11  / 2462MHz","traffic":5},"wp5g":{"actualChannel":"36  / 5180MHz"},"wp6g":null}`)
		case "/openapi/v1/abc123/sites/s1/aps/aa-bb-cc-dd-ee-01/available-channel":
			writeEnvelope(w, 0, "", `{"wp2g":[1,6,11],"wp5g":[36,40]}`)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	rows, err := c.GetAPChannels(context.Background(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("got %d APs, want 1", len(rows))
	}
	row := rows[0]
	if row.Name != "AP-01" || row.MAC != "AA-BB-CC-DD-EE-01" || len(row.CurrentChannels) != 2 || row.CurrentChannels["wp2g"] != "11  / 2462MHz" || row.CurrentChannels["wp5g"] != "36  / 5180MHz" || string(row.AvailableChannels) != `{"wp2g":[1,6,11],"wp5g":[36,40]}` {
		t.Errorf("unexpected AP row: %+v", row)
	}
}

func TestGetAPChannelsReadError(t *testing.T) {
	for _, endpoint := range []string{"radios", "available-channel"} {
		t.Run(endpoint, func(t *testing.T) {
			c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/openapi/v1/abc123/sites/s1/networks/devices":
					writeEnvelope(w, 0, "", `[{"type":"ap","mac":"aa-bb-cc-dd-ee-01"}]`)
				case "/openapi/v1/abc123/sites/s1/aps/aa-bb-cc-dd-ee-01/" + endpoint:
					writeEnvelope(w, -1600, "Unsupported request path.", `null`)
				case "/openapi/v1/abc123/sites/s1/aps/aa-bb-cc-dd-ee-01/radios":
					writeEnvelope(w, 0, "", `{}`)
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			rows, err := c.GetAPChannels(context.Background(), "s1")
			if rows != nil || err == nil || !strings.Contains(err.Error(), "controller error -1600") {
				t.Fatalf("rows = %v, error = %v", rows, err)
			}
		})
	}
}
