package testutil

import (
	"strings"
	"testing"
)

func TestSNATModeBody(t *testing.T) {
	for _, mode := range []string{"automatic", "hybrid", "advanced", "disabled"} {
		body := SNATModeBody(mode)
		if !strings.Contains(body, `"`+mode+`":{"selected":1}`) {
			t.Errorf("SNATModeBody(%q) = %s, want %q marked selected", mode, body, mode)
		}
		for _, other := range []string{"automatic", "hybrid", "advanced", "disabled"} {
			if other == mode {
				continue
			}
			if strings.Contains(body, `"`+other+`":{"selected":1}`) {
				t.Errorf("SNATModeBody(%q) also marks %q selected: %s", mode, other, body)
			}
		}
	}

	drift := SNATModeBody("")
	if !strings.Contains(drift, `"general":{}`) {
		t.Errorf("SNATModeBody(\"\") = %s, want snat_mode key omitted", drift)
	}
	if strings.Contains(drift, "snat_mode") {
		t.Errorf("SNATModeBody(\"\") must not contain snat_mode: %s", drift)
	}
}
