package cli

import (
	"strings"
	"testing"
)

func TestOmadaUnblockConfirmation(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--mac", "00:00:00:00:00:01"}, "requires --confirm"},
		{[]string{"--confirm"}, "requires --mac"},
	} {
		cmd := buildOmadaUnblockClientCmd()
		cmd.SetArgs(tc.args)
		if err := cmd.Execute(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v returned %v", tc.args, err)
		}
	}
}
