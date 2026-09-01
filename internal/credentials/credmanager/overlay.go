package credmanager

import "fmt"

// entryPrefix namespaces nyx's entries inside the user's Credential
// Manager. One prefix per controller family; the opnsense twin is a
// tracked follow-up.
const entryPrefix = "nyx-omada-"

// entryName returns the Credential Manager target for a controller
// host: `nyx-omada-<host>`. The host is the entry's identifier, so a
// WM entry can supply credentials but never the host itself.
func entryName(host string) string {
	return entryPrefix + host
}

// OverlayOmada fills empty ClientID/ClientSecret fields from the
// Windows Credential Manager entry named after host. Fill-only:
// values already present (from flags, env vars, or an earlier layer)
// always win. Read failures are silently ignored — the encrypted
// store remains the last fallback and the missing-credentials error
// stays actionable. The secret is never logged.
//
// On non-Windows platforms this is a no-op (Reader reports
// ErrUnsupported).
func OverlayOmada(host, clientID, clientSecret string) (string, string) {
	if host == "" || (clientID != "" && clientSecret != "") {
		return clientID, clientSecret
	}
	cred, found, err := reader.Read(entryName(host))
	if err != nil || !found {
		return clientID, clientSecret
	}
	if clientID == "" {
		clientID = cred.ClientID
	}
	if clientSecret == "" {
		clientSecret = cred.ClientSecret
	}
	return clientID, clientSecret
}

// Hint is the credential-manager clause appended to missing-credential
// error messages: it names the entry and the command that creates it,
// never the secret.
func Hint(host string) string {
	if host == "" {
		return ""
	}
	return fmt.Sprintf(" or use a Windows Credential Manager entry %s (cmdkey /generic:%s /user:<client-id> /pass:<client-secret>)",
		entryName(host), entryName(host))
}
