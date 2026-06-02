package batfish

import "testing"

func TestAvailable(t *testing.T) {
	if Available() {
		t.Error("batfish should not be available in v1")
	}
}

func TestErrNotImplemented(t *testing.T) {
	if ErrNotImplemented == nil {
		t.Fatal("ErrNotImplemented must be non-nil")
	}
	if ErrNotImplemented.Error() == "" {
		t.Error("ErrNotImplemented should have a message")
	}
}
