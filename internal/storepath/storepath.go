// Package storepath resolves the encrypted credential store location shared
// by the CLI and the MCP server: NYX_CREDENTIALS_FILE when set, else the
// default (~/.nyx/credentials.json).
package storepath

import (
	"os"

	"github.com/jpvelasco/nyx/internal/credentials"
)

// StoreFile returns the credential store path from the environment at call
// time, so the NYX_CREDENTIALS_FILE override is always honored.
func StoreFile() string {
	if p := os.Getenv("NYX_CREDENTIALS_FILE"); p != "" {
		return p
	}
	return credentials.DefaultPath()
}

// FirstNonEmpty returns the first non-empty value, or "" when all are empty.
func FirstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
