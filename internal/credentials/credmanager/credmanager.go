// Package credmanager reads generic entries from the Windows Credential
// Manager (Win32 CredReadW).
//
// On non-Windows platforms the reader always reports the entry as
// missing and returns ErrUnsupported; callers treat that like any
// other miss — the encrypted store (credentials.Overlay) remains the
// last fallback and the missing-credentials error stays actionable.
//
// Entry naming: `nyx-omada-<host>` carries the client ID in the entry
// user name (CRED_USERNAME) and the client secret in the password/blob
// (cmdkey /generic /user /pass). Secrets are never logged or written
// to evidence.
package credmanager

import "errors"

// ErrUnsupported is returned by the platform reader on platforms
// without a Credential Manager.
var ErrUnsupported = errors.New("windows credential manager is not supported on this platform")

// Cred is a generic credential pair: the entry's user name
// (CRED_USERNAME) and the secret stored as the password/blob.
type Cred struct {
	ClientID     string
	ClientSecret string
}

// Reader reads one generic credential entry by target name. found is
// false when the entry does not exist; err is non-nil only on a real
// lookup failure (never for a plain miss).
type Reader interface {
	Read(target string) (Cred, bool, error)
}

// reader is the platform reader (see reader_windows.go / reader_other.go).
// Tests replace it with a fake to unit-test the precedence chain.
var reader Reader = platformReader()

// SetReader overrides the platform reader. Tests only; pass nil to
// restore the platform default.
func SetReader(r Reader) {
	if r == nil {
		reader = platformReader()
		return
	}
	reader = r
}
