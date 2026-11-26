package omada

import (
	"net/http"
	"testing"
)

func TestGetClientHistory(t *testing.T) {
	calls := 0
	c, _ := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != http.MethodGet || r.URL.Path != "/openapi/v1/abc123/sites/s1/clients/02-aa-bb-cc-dd-01/client-history" {
			t.Errorf("unexpected request path or method")
		}
		writeEnvelope(w, 0, "", `[{"mac":"02:aa:bb:cc:dd:01","deviceName":"switch","port":8,"vid":30,"ssid":"gaming","lastSeen":100}]`)
	}))
	if _, err := c.GetClientHistory(t.Context(), "s1", "invalid"); err == nil {
		t.Fatal("accepted invalid client MAC")
	}
	rows, err := c.GetClientHistory(t.Context(), "s1", "02:aa:bb:cc:dd:01")
	if err != nil || calls != 1 || len(rows) != 1 || rows[0].Port != 8 || rows[0].VLAN != 30 || rows[0].LastSeen != 100 {
		t.Fatalf("history: %+v, %v", rows, err)
	}
}
