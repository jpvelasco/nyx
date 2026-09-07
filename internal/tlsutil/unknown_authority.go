// Package tlsutil holds shared TLS helpers used by both controller
// clients and the CLI fetch-cert command.
package tlsutil

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
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

// FetchOptions control FetchAndWrite.
type FetchOptions struct {
	// Host is host[:port]. A missing port defaults to 443.
	Host string
	// Out is the PEM destination path.
	Out string
	// Timeout bounds the TLS handshake. Zero uses 10s.
	Timeout time.Duration
	// Force overwrites an existing Out file.
	Force bool
}

// FetchAndWrite dials Host with InsecureSkipVerify solely to retrieve the
// presented certificate chain, then writes the chain as PEM (leaf first)
// to Out at 0600. It refuses to overwrite unless Force is set.
func FetchAndWrite(opts FetchOptions) (n int, err error) {
	if strings.TrimSpace(opts.Host) == "" {
		return 0, errors.New("host is required: pass --host")
	}
	if strings.TrimSpace(opts.Out) == "" {
		return 0, errors.New("--out is required: path to write the PEM")
	}
	if !opts.Force {
		if _, statErr := os.Stat(opts.Out); statErr == nil {
			return 0, fmt.Errorf("%s exists; pass --force to overwrite", opts.Out)
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return 0, fmt.Errorf("checking %s: %w", opts.Out, statErr)
		}
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	certs, err := fetchChain(opts.Host, timeout)
	if err != nil {
		return 0, err
	}
	if err := writePEM(opts.Out, certs); err != nil {
		return 0, err
	}
	return len(certs), nil
}

func fetchChain(host string, timeout time.Duration) ([]*x509.Certificate, error) {
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimRight(host, "/")
	addr := host
	if _, _, err := net.SplitHostPort(host); err != nil {
		addr = net.JoinHostPort(host, "443")
	}
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		// nosemgrep: this is a cert-extraction helper, not a data-plane call
		InsecureSkipVerify: true, // #nosec G402 — fetch-cert must see the presented chain
		MinVersion:         tls.VersionTLS12,
	})
	if err != nil {
		return nil, fmt.Errorf("fetching certificate chain: %w", err)
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, errors.New("fetching certificate chain: server presented no certificates")
	}
	return state.PeerCertificates, nil
}

func writePEM(path string, certs []*x509.Certificate) error {
	var buf bytes.Buffer
	for _, c := range certs {
		if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}); err != nil {
			return fmt.Errorf("encoding certificate: %w", err)
		}
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil { // nosemgrep
		return fmt.Errorf("writing PEM: %w", err)
	}
	return nil
}
