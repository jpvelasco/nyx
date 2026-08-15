// Package batfish is an intentional v2 placeholder: Batfish network-analysis
// integration is not implemented and this package is NOT wired into the audit
// engine or any backend registry. Available() always returns false and every
// operation returns ErrNotImplemented. Do not treat it as a live backend.
package batfish

import "errors"

// ErrNotImplemented is returned when Batfish operations are attempted in v1.
var ErrNotImplemented = errors.New("batfish backend is not yet implemented; planned for v2")

// Available returns false in v1; Batfish integration is not yet supported.
func Available() bool {
	return false
}
