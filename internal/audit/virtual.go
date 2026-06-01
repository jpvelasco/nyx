package audit

import (
	"net"
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

// vmIfaceSubstrings are name fragments that identify virtual adapters.
// Used as a fallback when nmap finds 0 hosts (no MAC in evidence).
var vmIfaceSubstrings = []string{
	"vmnet", "vboxnet", "veth", "docker", "br-", "virbr",
	"vmware", "virtualbox", "hyper-v", "wsl", "vethernet",
	"tap adapter", "tun driver", "openvpn",
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

// looksVirtualByCIDR returns true if the local interface that owns cidr has a
// virtual adapter name. Used when nmap finds 0 hosts and reports no MACs.
func looksVirtualByCIDR(cidr string) bool {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ip, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ipNet.Contains(ip.IP) {
				return isVirtualIfaceName(iface.Name)
			}
		}
	}
	return false
}

func isVirtualIfaceName(name string) bool {
	lower := strings.ToLower(name)
	for _, s := range vmIfaceSubstrings {
		if strings.HasPrefix(lower, s) || strings.Contains(lower, s) {
			return true
		}
	}
	return false
}
