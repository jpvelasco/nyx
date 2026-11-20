// Package textsafe makes untrusted device-supplied text safe to print.
package textsafe

import (
	"strings"
	"unicode"
)

// Printable removes control characters, invisible formatting (including
// bidirectional overrides), and line/paragraph separators, so text from a
// device or controller (a DHCP hostname, say) cannot inject terminal
// escapes or visually spoof the surrounding output.
func Printable(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp) {
			return -1
		}
		return r
	}, s)
}
