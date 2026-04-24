// Package batfish is a stub for future Batfish network-analysis integration.
// Full support is planned for v2 of netaudit.
package batfish

import "errors"

// ErrNotImplemented is returned when Batfish operations are attempted in v1.
var ErrNotImplemented = errors.New("batfish backend is not yet implemented; planned for v2")

// Available returns false in v1; Batfish integration is not yet supported.
func Available() bool {
	return false
}
