package testutil

import (
	"strings"
	"testing"
)

func TestWriteBody(t *testing.T) {
	const body = `{"errorCode":0,"result":"success"}`

	var buf strings.Builder
	n, err := WriteBody(&buf, body)
	if err != nil {
		t.Fatalf("WriteBody returned error: %v", err)
	}
	if n != len(body) {
		t.Fatalf("WriteBody wrote %d bytes, want %d", n, len(body))
	}
	if got := buf.String(); got != body {
		t.Fatalf("body = %q, want %q", got, body)
	}
}

func TestWriteBodyEmpty(t *testing.T) {
	var buf strings.Builder
	n, err := WriteBody(&buf, "")
	if err != nil {
		t.Fatalf("WriteBody returned error: %v", err)
	}
	if n != 0 {
		t.Fatalf("WriteBody wrote %d bytes, want 0", n)
	}
	if buf.Len() != 0 {
		t.Fatalf("buffer not empty after writing zero-length body")
	}
}
