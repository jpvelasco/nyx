package cli

import (
	"fmt"

	"github.com/jpvelasco/nyx/internal/models"
)

// ExitError carries a process exit code out of a cobra RunE so that
// cmd/nyx/main.go can map it centrally. Returning this instead of calling
// os.Exit inside RunE keeps deferred cleanup (e.g. --output writer flush)
// running before the process terminates.
type ExitError struct {
	Code int
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("exit code %d", e.Code)
}

// exitCodeForStatus maps a check status to the documented process exit code
// contract: 0 pass, 1 fail, 2 error, 3 warn.
func exitCodeForStatus(s models.Status) int {
	switch s {
	case models.StatusFail:
		return 1
	case models.StatusError:
		return 2
	case models.StatusWarn:
		return 3
	default:
		return 0
	}
}

// statusExitError returns an ExitError for a non-passing status, or nil when
// the status implies exit code 0. Use it after rendering so every output
// path (human and JSON) honors the exit-code contract.
func statusExitError(status models.Status) error {
	if code := exitCodeForStatus(status); code != 0 {
		return &ExitError{Code: code}
	}
	return nil
}
