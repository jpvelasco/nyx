package fake

import (
	"encoding/binary"
	"testing"
)

func TestCommandFromExecPayload(t *testing.T) {
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, uint32(len("echo hi")))
	payload = append(payload, []byte("echo hi")...)
	if got := CommandFromExecPayload(payload); got != "echo hi" {
		t.Errorf("got %q", got)
	}
	if got := CommandFromExecPayload(nil); got != "" {
		t.Errorf("empty payload should give empty command, got %q", got)
	}
	if got := CommandFromExecPayload([]byte{0, 0, 0, 99, 'a'}); got != "a" {
		t.Errorf("oversized length should fall back, got %q", got)
	}
}
