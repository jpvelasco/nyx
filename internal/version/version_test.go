package version

import "testing"

func TestVersionIsNotEmpty(t *testing.T) {
	if Version == "" {
		t.Skip("Version is empty (not set via ldflags)")
	}
}
