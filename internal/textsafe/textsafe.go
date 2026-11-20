// Package textsafe makes untrusted device-supplied text safe to print.
package textsafe

import (
	"strings"
	"unicode"

	"github.com/jpvelasco/nyx/internal/logger"
)

// Printable removes unsafe runes, for identifiers and names (a DHCP
// hostname, say) where a substitute character would change the value.
func Printable(s string) string { return replaceUnsafe(s, -1) }

// Message makes free-form controller text one printable line: unsafe runes
// become spaces so words stay apart, secrets are redacted by the shared
// logger scrubber, and surrounding space is trimmed.
func Message(s string) string {
	return strings.TrimSpace(string(logger.ScrubLine([]byte(replaceUnsafe(s, ' ')))))
}

// replaceUnsafe maps control characters, invisible formatting (including
// bidirectional overrides), and line/paragraph separators to with (-1
// drops them): runes that let device text inject terminal escapes or
// visually spoof the surrounding output.
func replaceUnsafe(s string, with rune) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return with
		}
		return r
	}, s)
}
