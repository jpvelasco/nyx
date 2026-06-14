package version

import "testing"

func TestVersionIsNotEmpty(t *testing.T) {
	if Version == "" {
		t.Error("Version should not be empty")
	}
}
