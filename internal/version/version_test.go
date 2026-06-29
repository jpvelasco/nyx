package version

import (
	"testing"
)

func TestVersionString(t *testing.T) {
	if Version == "" {
		t.Error("expected non-empty version string")
	}
}
