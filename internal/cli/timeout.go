package cli

import (
	"fmt"
	"time"
)

// parseTimeoutFlag parses the shared --timeout flag. A value that does not
// parse is an error (exit 2 via cli.Execute) rather than a silent fallback
// to a default, so user typos surface instead of changing runtime silently.
func parseTimeoutFlag(value string) (time.Duration, error) {
	dur, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid --timeout %q: %w", value, err)
	}
	return dur, nil
}
