package testutil

import "strings"

// SNATModeBody renders the OPNsense /firewall/source_nat/get selected-map
// response for the given mode (automatic, hybrid, advanced, disabled). The
// selected entry is the one whose selected flag is 1; an empty mode omits
// the snat_mode key entirely (simulating version key drift).
func SNATModeBody(mode string) string {
	if mode == "" {
		return `{"filter":{"general":{}}}`
	}
	selected := `{"automatic":{"selected":0},"hybrid":{"selected":0},"advanced":{"selected":0},"disabled":{"selected":0}}`
	selected = strings.Replace(selected, `"`+mode+`":{"selected":0}`, `"`+mode+`":{"selected":1}`, 1)
	return `{"filter":{"general":{"snat_mode":` + selected + `}}}`
}
