package cli

import (
	"strings"
	"testing"
	"time"
)

func TestParseTimeoutFlag_Valid(t *testing.T) {
	dur, err := parseTimeoutFlag("90s")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dur != 90*time.Second {
		t.Errorf("got %v, want 90s", dur)
	}
}

func TestParseTimeoutFlag_Invalid(t *testing.T) {
	_, err := parseTimeoutFlag("bogus")
	if err == nil {
		t.Fatal("expected error for invalid timeout")
	}
	if !strings.Contains(err.Error(), `invalid --timeout "bogus"`) {
		t.Errorf("error should name the flag value, got: %v", err)
	}
}
