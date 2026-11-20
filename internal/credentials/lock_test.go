package credentials

import (
	"errors"
	"fmt"
	"io/fs"
	"testing"
)

func TestRetryNotExist(t *testing.T) {
	errDenied := errors.New("permission denied")
	notExist := fmt.Errorf("openat lock: %w", fs.ErrNotExist)
	tests := []struct {
		name      string
		failures  int   // leading calls that fail with failErr
		failErr   error // error returned by those leading calls
		wantCalls int
		wantErr   error
	}{
		{name: "first try succeeds", failures: 0, wantCalls: 1},
		{name: "transient ENOENT then success", failures: 2, failErr: notExist, wantCalls: 3},
		{name: "persistent ENOENT gives up", failures: lockOpenAttempts, failErr: notExist, wantCalls: lockOpenAttempts, wantErr: fs.ErrNotExist},
		{name: "other errors are not retried", failures: 1, failErr: errDenied, wantCalls: 1, wantErr: errDenied},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			got, err := retryNotExist(func() (int, error) {
				calls++
				if calls <= tt.failures {
					return 0, tt.failErr
				}
				return 42, nil
			})
			if calls != tt.wantCalls {
				t.Errorf("calls = %d, want %d", calls, tt.wantCalls)
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr == nil && got != 42 {
				t.Errorf("value = %d, want 42", got)
			}
		})
	}
}
