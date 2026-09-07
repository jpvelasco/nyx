package tlsutil

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/testutil"
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

func TestFetchAndWrite_WritesVerifiablePEM(t *testing.T) {
	url, _ := testutil.CASignedServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	host := strings.TrimPrefix(url, "https://")
	out := filepath.Join(t.TempDir(), "controller.pem")
	n, err := FetchAndWrite(FetchOptions{Host: host, Out: out})
	if err != nil {
		t.Fatalf("FetchAndWrite: %v", err)
	}
	if n < 1 {
		t.Fatalf("wrote %d certs, want at least the leaf", n)
	}
	pemData, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading written PEM: %v", err)
	}
	var der []byte
	rest := pemData
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		der = append(der, block.Bytes...)
	}
	certs, err := x509.ParseCertificates(der)
	if err != nil {
		t.Fatalf("ParseCertificates: %v", err)
	}
	if len(certs) < 1 {
		t.Fatal("no certs in written PEM")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemData) {
		t.Fatal("written PEM did not parse as a CA pool")
	}
}

func TestFetchAndWrite_RefusesOverwrite(t *testing.T) {
	url, _ := testutil.CASignedServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	host := strings.TrimPrefix(url, "https://")
	out := filepath.Join(t.TempDir(), "exists.pem")
	if err := os.WriteFile(out, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := FetchAndWrite(FetchOptions{Host: host, Out: out})
	if err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("error = %v, want --force overwrite refusal", err)
	}
	got, _ := os.ReadFile(out)
	if string(got) != "keep" {
		t.Error("file was overwritten without --force")
	}
	n, err := FetchAndWrite(FetchOptions{Host: host, Out: out, Force: true})
	if err != nil {
		t.Fatalf("force overwrite: %v", err)
	}
	if n < 1 {
		t.Fatalf("force wrote %d certs", n)
	}
}

func TestFetchAndWrite_MissingArgs(t *testing.T) {
	if _, err := FetchAndWrite(FetchOptions{Out: "x.pem"}); err == nil || !strings.Contains(err.Error(), "host is required") {
		t.Errorf("missing host: %v", err)
	}
	if _, err := FetchAndWrite(FetchOptions{Host: "127.0.0.1"}); err == nil || !strings.Contains(err.Error(), "--out is required") {
		t.Errorf("missing out: %v", err)
	}
}
