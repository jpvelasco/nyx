package probe

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestCheckUnreachable(t *testing.T) {
	// RFC5737 non-routable address — should fail
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	p := Probe{
		Name: "test",
		Host: "192.0.2.1",
		User: "testuser",
		VLAN: "test",
	}
	err := Check(ctx, p)
	if err == nil {
		t.Fatal("expected error for unreachable host")
	}
}

func TestRunUnreachable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	p := Probe{
		Name: "test",
		Host: "192.0.2.1",
		User: "testuser",
		VLAN: "iot",
	}
	_, err := Run(ctx, p, []string{"echo", "hello"})
	if err == nil {
		t.Fatal("expected error for unreachable host")
	}
	if !strings.Contains(err.Error(), `probe "test"`) {
		t.Errorf("error should mention probe name, got: %v", err)
	}
}

func TestShellQuote(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"simple", "'simple'"},
		{"with space", "'with space'"},
		{"has'quote", "'has'\\''quote'"},
		{"", "''"},
		{"multiple'quotes'here", "'multiple'\\''quotes'\\''here'"},
		{"$dollar `backtick`", "'$dollar `backtick`'"},
	}
	for _, tt := range tests {
		if got := shellQuote(tt.in); got != tt.want {
			t.Errorf("shellQuote(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
