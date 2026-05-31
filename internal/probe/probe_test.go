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
