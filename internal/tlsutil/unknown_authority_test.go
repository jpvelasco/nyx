package tlsutil

import (
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestAnnotate_UnknownAuthority(t *testing.T) {
	got := Annotate(x509.UnknownAuthorityError{})
	if got == nil {
		t.Fatal("Annotate returned nil")
	}
	msg := got.Error()
	if !strings.Contains(msg, "--ca-cert") {
		t.Errorf("annotated error %q does not name --ca-cert", msg)
	}
	if !strings.Contains(msg, "--skip-tls-verify") {
		t.Errorf("annotated error %q does not name --skip-tls-verify", msg)
	}
	if !errors.As(got, &x509.UnknownAuthorityError{}) {
		t.Error("annotated error no longer unwraps to UnknownAuthorityError")
	}
	if !IsUnknownAuthority(got) {
		t.Error("IsUnknownAuthority(annotated) = false, want true")
	}
}

func TestAnnotate_OtherErrorsUnchanged(t *testing.T) {
	if Annotate(nil) != nil {
		t.Error("Annotate(nil) should stay nil")
	}
	orig := errors.New("connection refused")
	if got := Annotate(orig); got != orig {
		t.Errorf("Annotate(other) = %v, want the same error", got)
	}
	if IsUnknownAuthority(orig) {
		t.Error("IsUnknownAuthority(connection refused) = true, want false")
	}
}

func TestAnnotate_FmtWrapped(t *testing.T) {
	wrapped := fmt.Errorf("http request: %w", x509.UnknownAuthorityError{})
	got := Annotate(wrapped)
	if !IsUnknownAuthority(got) {
		t.Fatalf("expected unknown-authority after annotate, got %v", got)
	}
	if !strings.Contains(got.Error(), Hint) {
		t.Errorf("missing hint in %q", got)
	}
}
