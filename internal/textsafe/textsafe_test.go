package textsafe

import "testing"

func TestPrintable(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"plain", "desk", "desk"},
		{"ansi escape", "\x1b[2J\x1b[31mdesk", "[2J[31mdesk"},
		{"bell and newline", "de\asK\n", "desK"},
		{"bidi override", "desk\u202eexe.", "deskexe."},
		{"zero-width joiner", "de\u200dsk", "desk"},
		{"line separator", "de\u2028sk", "desk"},
		{"unicode letters kept", "café-π", "café-π"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Printable(tc.in); got != tc.want {
				t.Errorf("Printable(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestMessage(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"plain", "radio busy", "radio busy"},
		{"ansi escape spaced", "\x1b[2Jbad\nstate", "[2Jbad state"},
		{"bidi and separator spaced", "bad\u202eradio\u2028state", "bad radio state"},
		{"trimmed", "\tbusy\r\n", "busy"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Message(tc.in); got != tc.want {
				t.Errorf("Message(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
