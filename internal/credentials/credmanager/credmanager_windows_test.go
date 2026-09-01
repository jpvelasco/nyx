//go:build windows

package credmanager

import (
	"testing"
	"unsafe"
)

// TestCredentialWLayout pins the CREDENTIALW field offsets against the
// Win32 header layout. This file only compiles on the Windows CI leg,
// which keeps the fixed C struct covered there. The layout the live
// reader relies on (userName @72, blob @40) is confirmed by a real
// CredReadW decode, so these pins guard against a future Go struct drift.
func TestCredentialWLayout(t *testing.T) {
	var c credW
	want := map[string]uintptr{
		"flags":          0,
		"credType":       4,
		"targetName":     8,
		"comment":        16,
		"lastWritten":    24,
		"credBlobSize":   32,
		"credBlob":       40,
		"persist":        48,
		"attributeCount": 52,
		"attributes":     56,
		"targetAlias":    64,
		"userName":       72,
	}
	if got := uintptr(unsafe.Sizeof(c)); got != 80 {
		t.Fatalf("Sizeof(credW) = %d, want 80", got)
	}
	check := func(name string, off uintptr) {
		t.Helper()
		if want[name] != off {
			t.Errorf("Offsetof(credW.%s) = %d, want %d", name, off, want[name])
		}
	}
	check("flags", unsafe.Offsetof(c.flags))
	check("credType", unsafe.Offsetof(c.credType))
	check("targetName", unsafe.Offsetof(c.targetName))
	check("comment", unsafe.Offsetof(c.comment))
	check("lastWritten", unsafe.Offsetof(c.lastWritten))
	check("credBlobSize", unsafe.Offsetof(c.credBlobSize))
	check("credBlob", unsafe.Offsetof(c.credBlob))
	check("persist", unsafe.Offsetof(c.persist))
	check("attributeCount", unsafe.Offsetof(c.attributeCount))
	check("attributes", unsafe.Offsetof(c.attributes))
	check("targetAlias", unsafe.Offsetof(c.targetAlias))
	check("userName", unsafe.Offsetof(c.userName))
}

// TestReadUTF16 exercises the two decode paths (NUL-terminated string and
// raw blob) against in-test memory.
func TestReadUTF16(t *testing.T) {
	// "hi\x00" -> 2 words + NUL
	nulStr := [3]uint16{'h', 'i', 0}
	if got := readUTF16(unsafe.Pointer(&nulStr[0])); got != "hi" {
		t.Fatalf("NUL-terminated decode = %q, want hi", got)
	}
	// blob without a trailing NUL: 4 bytes = "hi" in UTF-16
	blob := [4]byte{'h', 0, 'i', 0}
	if got := readUTF16(unsafe.Pointer(&blob[0]), 4); got != "hi" {
		t.Fatalf("blob decode = %q, want hi", got)
	}
	// zero-length blob
	if got := readUTF16(unsafe.Pointer(&blob[0]), 0); got != "" {
		t.Fatalf("empty blob decode = %q, want empty", got)
	}
	// nil pointer (a field CredReadW left unset) decodes as ""
	if got := readUTF16(nil, 4); got != "" {
		t.Fatalf("nil decode = %q, want empty", got)
	}
	if got := readUTF16(nil); got != "" {
		t.Fatalf("nil NUL-scan decode = %q, want empty", got)
	}
}

// TestWindowsReaderMissingTarget reads a target that cannot exist and
// expects a clean miss (found=false, nil error) — this runs the real
// CredReadW path on the Windows leg.
func TestWindowsReaderMissingTarget(t *testing.T) {
	cred, found, err := (windowsReader{}).Read("nyx-test-missing-target-0d4f")
	if err != nil {
		t.Fatalf("Read: unexpected error %v", err)
	}
	if found {
		t.Fatalf("found = true, want false")
	}
	if cred.ClientID != "" || cred.ClientSecret != "" {
		t.Fatalf("cred = %+v, want zero", cred)
	}
}
