package cli

import (
	"strings"
	"testing"
)

func TestOpnsenseStatesConfirmation(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"kill", "--state", "abcd/1234"}, "requires --confirm"},
		{[]string{"kill", "--confirm"}, "supply --state"},
		{[]string{"kill", "--state", "abcd/1234", "--filter", "fixture", "--confirm"}, "supply --state"},
		{[]string{"flush-states"}, "requires --confirm"},
		{[]string{"flush-sources", "--confirm=false"}, "requires --confirm"},
	} {
		cmd := buildOpnsenseStatesCmd()
		cmd.SetArgs(tc.args)
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v returned %v", tc.args, err)
		}
	}
}
