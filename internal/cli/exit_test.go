package cli

import (
	"errors"
	"testing"

	"github.com/jpvelasco/nyx/internal/models"
)

func TestExitCodeForStatus(t *testing.T) {
	tests := []struct {
		status models.Status
		want   int
	}{
		{models.StatusPass, 0},
		{models.StatusFail, 1},
		{models.StatusError, 2},
		{models.StatusWarn, 3},
		{models.StatusSkip, 0},
		{"", 0},
	}
	for _, tt := range tests {
		if got := exitCodeForStatus(tt.status); got != tt.want {
			t.Errorf("exitCodeForStatus(%s) = %d, want %d", tt.status, got, tt.want)
		}
	}
}

func TestStatusExitError(t *testing.T) {
	if err := statusExitError(models.StatusPass); err != nil {
		t.Errorf("pass should be nil error, got %v", err)
	}
	for status, code := range map[models.Status]int{
		models.StatusFail:  1,
		models.StatusError: 2,
		models.StatusWarn:  3,
	} {
		err := statusExitError(status)
		if err == nil {
			t.Fatalf("expected error for %s", status)
		}
		var ee *ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("expected *ExitError, got %T", err)
		}
		if ee.Code != code {
			t.Errorf("statusExitError(%s).Code = %d, want %d", status, ee.Code, code)
		}
	}
}

func TestExitError_Error(t *testing.T) {
	if got := (&ExitError{Code: 3}).Error(); got != "exit code 3" {
		t.Errorf("Error() = %q", got)
	}
}

// requireExitCode asserts that err is an *ExitError carrying the given code,
// failing the test otherwise.
func requireExitCode(t *testing.T, err error, want int) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected exit code %d, got nil error", want)
	}
	var ee *ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("expected *ExitError, got %T (%v)", err, err)
	}
	if ee.Code != want {
		t.Errorf("expected exit code %d, got %d", want, ee.Code)
	}
}
