//go:build !windows

package credmanager

import "testing"

// TestPlatformReaderUnsupported pins the non-Windows stub: the default
// platform reader reports ErrUnsupported so OverlayOmada degrades to a
// silent no-op and the encrypted store remains the fallback.
func TestPlatformReaderUnsupported(t *testing.T) {
	cred, found, err := platformReader().Read("nyx-omada-omada.local")
	if err != ErrUnsupported {
		t.Fatalf("err = %v, want ErrUnsupported", err)
	}
	if found {
		t.Fatal("found = true, want false")
	}
	if cred != (Cred{}) {
		t.Fatalf("cred = %+v, want zero", cred)
	}
}
