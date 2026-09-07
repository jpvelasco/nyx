// Package tlsutil holds shared TLS helpers used by both controller clients.
package tlsutil

import (
	"crypto/x509"
	"errors"
	"fmt"
)

// Hint is the operator-facing text appended to unknown-authority
// failures. --ca-cert pinning is preferred; --skip-tls-verify is the
// self-signed opt-out. The text is host-free.
const Hint = "pin the controller CA with --ca-cert <pem> (preferred); --skip-tls-verify opts out of verification for a self-signed cert"

// Annotate wraps err when it is (or unwraps to) an unknown-authority TLS
// failure, pointing at --ca-cert pinning first and --skip-tls-verify as
// the self-signed opt-out. Other errors are returned unchanged.
func Annotate(err error) error {
	if err == nil || !IsUnknownAuthority(err) {
		return err
	}
	return fmt.Errorf("%w; %s", err, Hint)
}

// IsUnknownAuthority reports whether err is (or unwraps to) an
// x509.UnknownAuthorityError.
func IsUnknownAuthority(err error) bool {
	var ua x509.UnknownAuthorityError
	return errors.As(err, &ua)
}
