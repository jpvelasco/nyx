package main

import (
	"os"
	"testing"
)

func TestRun_Success(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"nyx", "version"}
	if code := run(); code != 0 {
		t.Errorf("expected exit code 0, got %d", code)
	}
}

func TestRun_Error(t *testing.T) {
	oldArgs := os.Args
	defer func() { os.Args = oldArgs }()
	os.Args = []string{"nyx", "--bogus-flag"}
	if code := run(); code != 2 {
		t.Errorf("expected exit code 2, got %d", code)
	}
}
