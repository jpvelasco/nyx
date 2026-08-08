package nmap

import (
	"fmt"
	"os/exec"
	"runtime"
)

// installCmd returns the recommended install command for nmap on the current OS.
func installCmd() string {
	return installCmdFor(runtime.GOOS, func(bin string) error {
		_, err := exec.LookPath(bin)
		return err
	})
}

// installCmdFor returns the recommended install command for nmap on the given
// OS, using lookup to detect available package managers on Linux.
func installCmdFor(goos string, lookup func(bin string) error) string {
	switch goos {
	case "windows":
		return "winget install nmap"
	case "darwin":
		return "brew install nmap"
	default:
		// Linux — detect package manager
		for _, pm := range []struct{ bin, cmd string }{
			{"apt-get", "sudo apt-get install -y nmap"},
			{"apt", "sudo apt install -y nmap"},
			{"dnf", "sudo dnf install -y nmap"},
			{"yum", "sudo yum install -y nmap"},
			{"pacman", "sudo pacman -S nmap"},
			{"apk", "sudo apk add nmap"},
		} {
			if lookup(pm.bin) == nil {
				return pm.cmd
			}
		}
		return "sudo <your-package-manager> install nmap"
	}
}

// CheckAvailable returns an error with actionable install instructions if nmap
// is not found in PATH. Returns nil when nmap is available.
func CheckAvailable() error {
	if Available() {
		return nil
	}
	return fmt.Errorf(
		"nmap is required but was not found in PATH\n\n"+
			"  Install it with:\n"+
			"    %s\n\n"+
			"  Then re-run this command",
		installCmd(),
	)
}
