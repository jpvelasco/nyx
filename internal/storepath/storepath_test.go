package storepath

import "testing"

// StoreFile's behavior (default path + NYX_CREDENTIALS_FILE override) is
// exercised by TestStoreFileDefault / TestStoreFileHonorsEnvOverride in
// internal/cli, which uses the helper the way the CLI and MCP server do.

func TestFirstNonEmpty(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"first non-empty wins", []string{"", "", "a", "b"}, "a"},
		{"first value", []string{"x", "y"}, "x"},
		{"all empty", []string{"", ""}, ""},
		{"no values", nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := FirstNonEmpty(tc.args...); got != tc.want {
				t.Errorf("FirstNonEmpty(%v) = %q, want %q", tc.args, got, tc.want)
			}
		})
	}
}
