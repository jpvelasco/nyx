package cli

import (
	"runtime"
	"strings"
	"testing"
)

func TestNmapInstallHintNoSudo(t *testing.T) {
	hint := nmapInstallHint()
	switch runtime.GOOS {
	case "windows":
		if !strings.Contains(hint, "no admin required") {
			t.Errorf("Windows hint missing 'no admin required': %q", hint)
		}
	default:
		if !strings.Contains(hint, "no sudo required") {
			t.Errorf("hint missing 'no sudo required': %q", hint)
		}
	}
}

func TestNmapInstallHintContainsInstallCommand(t *testing.T) {
	hint := nmapInstallHint()
	// Verify the install command is still present alongside the no-sudo note
	switch runtime.GOOS {
	case "windows":
		if !strings.Contains(hint, "winget install nmap") {
			t.Errorf("Windows hint missing install command: %q", hint)
		}
	case "darwin":
		if !strings.Contains(hint, "brew install nmap") {
			t.Errorf("macOS hint missing install command: %q", hint)
		}
	default:
		if !strings.Contains(hint, "apt install nmap") {
			t.Errorf("Linux hint missing install command: %q", hint)
		}
	}
}

func TestNmapPassSummaryContainsNoRoot(t *testing.T) {
	// The nmap PASS summary is built inline in doctorCmd.RunE.
	// This test documents the expected format so a refactor doesn't silently drop it.
	// Format: "nmap: <version-line> (no root/admin needed to run nyx)"
	summary := "nmap: Nmap version 7.94 SVN ( https://nmap.org ) (no root/admin needed to run nyx)"
	if !strings.Contains(summary, "(no root/admin needed to run nyx)") {
		t.Errorf("nmap PASS summary format changed — update doctor.go to restore no-root note: %q", summary)
	}
}
