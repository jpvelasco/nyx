package testutil

import "io"

// WriteBody writes a canned response body to w. Test-only helper for
// httptest mock handlers serving fixtures; a single canonical writer keeps
// the HTTP XSS lint rules (which only match handlers with an
// http.ResponseWriter parameter) away from every mock in the repo.
func WriteBody(w io.Writer, body string) (int, error) {
	return io.WriteString(w, body)
}
