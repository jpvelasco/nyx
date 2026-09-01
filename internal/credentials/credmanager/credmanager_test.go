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
