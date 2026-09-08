package credmanager

import (
	"errors"
	"testing"
)

// fakeReader is a controllable Reader for precedence-chain tests.
type fakeReader struct {
	cred     Cred
	found    bool
	err      error
	readCall int
	target   string
}

func (f *fakeReader) Read(target string) (Cred, bool, error) {
	f.readCall++
	f.target = target
	return f.cred, f.found, f.err
}

func TestOverlayOmadaPrecedence(t *testing.T) {
	restore := func() { t.Cleanup(func() { SetReader(nil) }) }

	t.Run("WM fills empty id and secret", func(t *testing.T) {
		restore()
		f := &fakeReader{cred: Cred{ClientID: "wm-id", ClientSecret: "wm-secret"}, found: true}
		SetReader(f)
		id, secret := OverlayOmada("omada.local", "", "")
		if id != "wm-id" || secret != "wm-secret" {
			t.Fatalf("got (%q, %q), want (wm-id, wm-secret)", id, secret)
		}
		if f.target != "nyx-omada-omada.local" {
			t.Fatalf("target = %q, want nyx-omada-omada.local", f.target)
		}
	})

	t.Run("flags and env win over WM", func(t *testing.T) {
		restore()
		f := &fakeReader{cred: Cred{ClientID: "wm-id", ClientSecret: "wm-secret"}, found: true}
		SetReader(f)
		// Flag/env-resolved id present, secret empty: only the empty slot
		// may be filled.
		id, secret := OverlayOmada("omada.local", "flag-id", "")
		if id != "flag-id" || secret != "wm-secret" {
			t.Fatalf("got (%q, %q), want (flag-id, wm-secret)", id, secret)
		}
		id, secret = OverlayOmada("omada.local", "flag-id", "flag-secret")
		if id != "flag-id" || secret != "flag-secret" {
			t.Fatalf("got (%q, %q), want (flag-id, flag-secret)", id, secret)
		}
	})

	t.Run("miss and read error are silent no-ops", func(t *testing.T) {
		restore()
		SetReader(&fakeReader{found: false})
		id, secret := OverlayOmada("omada.local", "env-id", "env-secret")
		if id != "env-id" || secret != "env-secret" {
			t.Fatalf("got (%q, %q), want unchanged", id, secret)
		}
		SetReader(&fakeReader{err: errors.New("boom")})
		id, secret = OverlayOmada("omada.local", "env-id", "env-secret")
		if id != "env-id" || secret != "env-secret" {
			t.Fatalf("got (%q, %q), want unchanged", id, secret)
		}
	})

	t.Run("partial WM entry only fills the empty slot", func(t *testing.T) {
		restore()
		f := &fakeReader{cred: Cred{ClientID: ""}, found: true} // empty user name
		SetReader(f)
		id, secret := OverlayOmada("omada.local", "", "env-secret")
		if id != "" || secret != "env-secret" {
			t.Fatalf("got (%q, %q), want (, env-secret)", id, secret)
		}
	})

	t.Run("empty host never consults WM", func(t *testing.T) {
		restore()
		f := &fakeReader{cred: Cred{ClientID: "wm-id"}, found: true}
		SetReader(f)
		id, secret := OverlayOmada("", "", "")
		if id != "" || secret != "" {
			t.Fatalf("got (%q, %q), want empty", id, secret)
		}
		if f.readCall != 0 {
			t.Fatalf("readCall = %d, want 0 (WM must never supply the host)", f.readCall)
		}
	})
}

// TestOverlayOmadaDefaultReaderOffWindows covers the default-reader path
// (platformReader, not an injected fake) on non-Windows legs: the stub
// reader errors with ErrUnsupported, which the overlay must swallow
// silently, leaving the inputs untouched.
func TestOverlayOmadaDefaultReaderOffWindows(t *testing.T) {
	t.Cleanup(func() { SetReader(nil) })
	id, secret := OverlayOmada("omada.local", "", "")
	if id != "" || secret != "" {
		t.Fatalf("got (%q, %q), want untouched empty inputs", id, secret)
	}
}

func TestOverlayOpnsensePrecedence(t *testing.T) {
	restore := func() { t.Cleanup(func() { SetReader(nil) }) }

	t.Run("WM fills empty key and secret", func(t *testing.T) {
		restore()
		f := &fakeReader{cred: Cred{ClientID: "wm-key", ClientSecret: "wm-secret"}, found: true}
		SetReader(f)
		key, secret := OverlayOpnsense("fw.example", "", "")
		if key != "wm-key" || secret != "wm-secret" {
			t.Fatalf("got (%q, %q), want (wm-key, wm-secret)", key, secret)
		}
		if f.target != "nyx-opnsense-fw.example" {
			t.Fatalf("target = %q, want nyx-opnsense-fw.example", f.target)
		}
	})

	t.Run("flags and env win over WM", func(t *testing.T) {
		restore()
		f := &fakeReader{cred: Cred{ClientID: "wm-key", ClientSecret: "wm-secret"}, found: true}
		SetReader(f)
		// Flag/env-resolved key present, secret empty: only the empty slot
		// may be filled.
		key, secret := OverlayOpnsense("fw.example", "flag-key", "")
		if key != "flag-key" || secret != "wm-secret" {
			t.Fatalf("got (%q, %q), want (flag-key, wm-secret)", key, secret)
		}
		key, secret = OverlayOpnsense("fw.example", "flag-key", "flag-secret")
		if key != "flag-key" || secret != "flag-secret" {
			t.Fatalf("got (%q, %q), want (flag-key, flag-secret)", key, secret)
		}
	})

	t.Run("miss and read error are silent no-ops", func(t *testing.T) {
		restore()
		SetReader(&fakeReader{found: false})
		key, secret := OverlayOpnsense("fw.example", "env-key", "env-secret")
		if key != "env-key" || secret != "env-secret" {
			t.Fatalf("got (%q, %q), want unchanged", key, secret)
		}
		SetReader(&fakeReader{err: errors.New("boom")})
		key, secret = OverlayOpnsense("fw.example", "env-key", "env-secret")
		if key != "env-key" || secret != "env-secret" {
			t.Fatalf("got (%q, %q), want unchanged", key, secret)
		}
	})

	t.Run("partial WM entry only fills the empty slot", func(t *testing.T) {
		restore()
		f := &fakeReader{cred: Cred{ClientID: ""}, found: true} // empty user name
		SetReader(f)
		key, secret := OverlayOpnsense("fw.example", "", "env-secret")
		if key != "" || secret != "env-secret" {
			t.Fatalf("got (%q, %q), want (, env-secret)", key, secret)
		}
	})

	t.Run("empty host never consults WM", func(t *testing.T) {
		restore()
		f := &fakeReader{cred: Cred{ClientID: "wm-key"}, found: true}
		SetReader(f)
		key, secret := OverlayOpnsense("", "", "")
		if key != "" || secret != "" {
			t.Fatalf("got (%q, %q), want empty", key, secret)
		}
		if f.readCall != 0 {
			t.Fatalf("readCall = %d, want 0 (WM must never supply the host)", f.readCall)
		}
	})
}

// TestOverlayOpnsenseDefaultReaderOffWindows covers the default-reader path
// (platformReader, not an injected fake) on non-Windows legs: the stub
// reader errors with ErrUnsupported, which the overlay must swallow
// silently, leaving the inputs untouched.
func TestOverlayOpnsenseDefaultReaderOffWindows(t *testing.T) {
	t.Cleanup(func() { SetReader(nil) })
	key, secret := OverlayOpnsense("fw.example", "", "")
	if key != "" || secret != "" {
		t.Fatalf("got (%q, %q), want untouched empty inputs", key, secret)
	}
}

func TestEntryNameAndHint(t *testing.T) {
	if got := entryName("10.0.0.1"); got != "nyx-omada-10.0.0.1" {
		t.Fatalf("entryName = %q", got)
	}
	if got := Hint(""); got != "" {
		t.Fatalf("Hint(\"\") = %q, want empty", got)
	}
	want := " or use a Windows Credential Manager entry nyx-omada-omada.local (cmdkey /generic:nyx-omada-omada.local /user:<client-id> /pass:<client-secret>)"
	if got := Hint("omada.local"); got != want {
		t.Fatalf("Hint = %q, want %q", got, want)
	}
}

func TestHintOpnsense(t *testing.T) {
	if got := HintOpnsense(""); got != "" {
		t.Fatalf("HintOpnsense(\"\") = %q, want empty", got)
	}
	want := " or use a Windows Credential Manager entry nyx-opnsense-fw.example (cmdkey /generic:nyx-opnsense-fw.example /user:<api-key> /pass:<api-secret>)"
	if got := HintOpnsense("fw.example"); got != want {
		t.Fatalf("HintOpnsense = %q, want %q", got, want)
	}
}
