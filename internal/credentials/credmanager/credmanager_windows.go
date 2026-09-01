//go:build windows

package credmanager

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32     = windows.NewLazySystemDLL("advapi32.dll")
	procCredRead = advapi32.NewProc("CredReadW")
	procCredFree = advapi32.NewProc("CredFree")
)

// credW mirrors the CREDENTIALW layout from wincred.h (current layout,
// ends at TargetAlias). Field order and alignment follow the C header
// exactly; offsets are pinned by TestCredentialWLayout on the CI Windows
// leg. The struct is allocated by CredReadW; string fields point into
// memory released by a single CredFree.
type credW struct {
	flags          uint32
	credType       uint32
	targetName     *uint16
	comment        *uint16
	lastWritten    int64 // FILETIME
	credBlobSize   uint32
	credBlob       *byte
	persist        uint32
	attributeCount uint32
	attributes     *uint16
	targetAlias    *uint16
	userName       *uint16
}

// windowsReader reads generic Credential Manager entries.
type windowsReader struct{}

func platformReader() Reader { return windowsReader{} }

// Read returns the user name and secret blob of a generic credential
// entry. Missing entries (including access failures such as another
// logon session) report found=false with a nil error, so callers can
// fall through to the encrypted store.
func (windowsReader) Read(target string) (Cred, bool, error) {
	targetUTF16, err := syscall.UTF16FromString(target)
	if err != nil {
		return Cred{}, false, err
	}
	var outPtr *credW
	ret, _, _ := procCredRead.Call(
		uintptr(unsafe.Pointer(&targetUTF16[0])), // #nosec G103 - fixed NUL-terminated UTF-16 target // nosemgrep
		1,                                        // CRED_TYPE_GENERIC
		0,                                        // not an enterprise credential
		uintptr(unsafe.Pointer(&outPtr)),         // #nosec G103 - CREDENTIALW out-param // nosemgrep
	)
	// ret is the Win32 BOOL: CredReadW returns FALSE (and sets the last
	// error, e.g. ERROR_CREDENTIAL_UNKNOWN) when the entry does not
	// exist, so any failure degrades to a plain miss.
	if ret == 0 || outPtr == nil {
		return Cred{}, false, nil
	}
	defer procCredFree.Call(uintptr(unsafe.Pointer(outPtr))) // #nosec G103 - release CredReadW memory // nosemgrep
	return decodeCredential(outPtr), true, nil
}

// decodeCredential walks a CREDENTIALW mirror produced by CredReadW. The
// pointer fields point into memory owned by the caller and released with
// a single CredFree; for CRED_TYPE_GENERIC the password lives in the blob
// as UTF-16 without a trailing NUL (CredentialBlobSize is in bytes).
func decodeCredential(w *credW) Cred {
	userName := readUTF16(unsafe.Pointer(w.userName))                  // #nosec G103 - CREDENTIALW field // nosemgrep
	blob := readUTF16(unsafe.Pointer(w.credBlob), int(w.credBlobSize)) // #nosec G103 - CREDENTIALW field // nosemgrep
	return Cred{ClientID: userName, ClientSecret: blob}
}

// readUTF16 decodes a NUL-terminated UTF-16 string at p, or the first n
// bytes at p when n > 0 (the credential blob carries no NUL). A nil p
// (a field CredReadW left unset) decodes as "".
func readUTF16(p unsafe.Pointer, n ...int) string {
	if p == nil {
		return ""
	}
	var words int
	if len(n) > 0 {
		words = n[0] / 2
	} else {
		// CREDENTIALW string fields are NUL-terminated; the 4096-word
		// cap guards against a corrupted or hostile entry.
		for i := 0; i < 4096; i++ {
			if *(*uint16)(unsafe.Add(p, i*2)) == 0 { // nosemgrep
				words = i
				break
			}
		}
	}
	if words == 0 {
		return ""
	}
	return syscall.UTF16ToString(unsafe.Slice((*uint16)(p), words)) // #nosec G103 - bounded CREDENTIALW decode // nosemgrep
}
