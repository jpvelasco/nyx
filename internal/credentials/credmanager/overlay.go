package credmanager

import "fmt"

// One prefix per controller family. The host is the entry's identifier,
// so a WM entry can supply credentials but never the host itself.
const (
	omadaPrefix    = "nyx-omada-"
	opnsensePrefix = "nyx-opnsense-"
)

// entryName returns the Omada Credential Manager target for a controller
// host: `nyx-omada-<host>`.
func entryName(host string) string {
	return omadaPrefix + host
}

// overlay fills empty credential slots from the Windows Credential
// Manager entry named prefix+host. Fill-only: values already present
// (from flags, env vars, or an earlier layer) always win. Read
// failures are silently ignored — the encrypted store remains the last
// fallback and the missing-credentials error stays actionable. The
// secret is never logged.
//
// On non-Windows platforms this is a no-op (Reader reports
// ErrUnsupported).
func overlay(prefix, host, a, b string) (string, string) {
	if host == "" || (a != "" && b != "") {
		return a, b
	}
	cred, found, err := reader.Read(prefix + host)
	if err != nil || !found {
		return a, b
	}
	if a == "" {
		a = cred.ClientID
	}
	if b == "" {
		b = cred.ClientSecret
	}
	return a, b
}

// hintFor is the credential-manager clause appended to missing-credential
// error messages: it names the entry and the command that creates it,
// never the secret.
func hintFor(prefix, host, userPlaceholder, passPlaceholder string) string {
	if host == "" {
		return ""
	}
	name := prefix + host
	return fmt.Sprintf(" or use a Windows Credential Manager entry %s (cmdkey /generic:%s /user:<%s> /pass:<%s>)",
		name, name, userPlaceholder, passPlaceholder)
}

// OverlayOmada fills empty ClientID/ClientSecret fields from the
// Windows Credential Manager entry named after host (`nyx-omada-<host>`).
// Fill-only: values already present (from flags, env vars, or an earlier
// layer) always win. Read failures are silently ignored. The secret is
// never logged.
//
// On non-Windows platforms this is a no-op (Reader reports
// ErrUnsupported).
func OverlayOmada(host, clientID, clientSecret string) (string, string) {
	return overlay(omadaPrefix, host, clientID, clientSecret)
}

// OverlayOpnsense fills empty API key/secret fields from the Windows
// Credential Manager entry named after host (`nyx-opnsense-<host>`).
// Fill-only: values already present (from flags, env vars, or an earlier
// layer) always win. Read failures are silently ignored. The secret is
// never logged. A WM entry can supply credentials but never the host.
//
// On non-Windows platforms this is a no-op (Reader reports
// ErrUnsupported).
func OverlayOpnsense(host, apiKey, apiSecret string) (string, string) {
	return overlay(opnsensePrefix, host, apiKey, apiSecret)
}

// Hint is the Omada credential-manager clause appended to
// missing-credential error messages: it names the nyx-omada-<host>
// entry and the cmdkey that creates it, never the secret.
func Hint(host string) string {
	return hintFor(omadaPrefix, host, "client-id", "client-secret")
}

// HintOpnsense is the OPNsense credential-manager clause appended to
// missing-credential error messages: it names the nyx-opnsense-<host>
// entry and the cmdkey that creates it (`/user:<api-key>
// /pass:<api-secret>`), never the secret.
func HintOpnsense(host string) string {
	return hintFor(opnsensePrefix, host, "api-key", "api-secret")
}
