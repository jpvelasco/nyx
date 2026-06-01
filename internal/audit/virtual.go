package audit

import (
	"strings"
)

// vmMACPrefixes are the well-known OUI prefixes for virtual machine hypervisors.
// Hyper-V and WSL2 both use 00:15:5D.
var vmMACPrefixes = []string{
	"00:50:56", // VMware ESX/Workstation
	"00:0c:29", // VMware (dynamically assigned)
	"00:05:69", // VMware (older)
	"08:00:27", // VirtualBox
	"00:15:5d", // Hyper-V / WSL2
}

// looksVirtual returns true if any evidence line contains a known VM MAC prefix.
func looksVirtual(evidence []string) bool {
	for _, line := range evidence {
		lower := strings.ToLower(line)
		for _, prefix := range vmMACPrefixes {
			if strings.Contains(lower, prefix) {
				return true
			}
		}
	}
	return false
}
