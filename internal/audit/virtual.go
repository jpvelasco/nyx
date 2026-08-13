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

// virtualIfaceAddrs returns the addresses of virtual-named adapters
// (Hyper-V, WSL2, VMware, VirtualBox, Docker). Shared by both virtual
// detection paths so the adapter enumeration lives in one place.
func virtualIfaceAddrs() []net.IPNet {
	return virtualIfaceAddrsFrom(net.Interfaces)
}

// virtualIfaceAddrsFrom enumerates virtual-named adapter addresses from a
// provided interface source so the error path is unit-testable.
func virtualIfaceAddrsFrom(interfaces func() ([]net.Interface, error)) []net.IPNet {
	ifaces, err := interfaces()
	if err != nil {
		return nil
	}
	var out []net.IPNet
	for _, iface := range ifaces {
		if !isVirtualIfaceName(iface.Name) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			out = append(out, *ipNet)
		}
	}
	return out
}

// virtualNetworksFrom maps each IPv4 address to its /24 network. IPv6
// addresses are skipped; a machine has no virtual adapter when the input
// is empty.
func virtualNetworksFrom(addrs []net.IPNet) []string {
	var out []string
	mask24 := net.CIDRMask(24, 32)
	for _, ipNet := range addrs {
		ip4 := ipNet.IP.To4()
		if ip4 == nil {
			continue
		}
		out = append(out, (&net.IPNet{IP: ip4.Mask(mask24), Mask: mask24}).String())
	}
	return out
}

// VirtualIfaceNetworks returns the /24 network CIDRs owned by virtual
// adapters (Hyper-V, WSL2, VMware, VirtualBox, Docker). Used by tests to
// scan a small slice of a virtual subnet deterministically. Empty when the
// machine has no virtual adapter.
func VirtualIfaceNetworks() []string {
	return virtualNetworksFrom(virtualIfaceAddrs())
}

// looksVirtualByCIDR returns true if the local interface that owns cidr has a
// virtual adapter name. Used when nmap finds 0 hosts and reports no MACs.
func looksVirtualByCIDR(cidr string) bool {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return anyAddrIn(virtualIfaceAddrs(), ipNet)
}

// anyAddrIn reports whether any of the addresses falls inside ipNet.
func anyAddrIn(addrs []net.IPNet, ipNet *net.IPNet) bool {
	for _, addr := range addrs {
		if ipNet.Contains(addr.IP) {
			return true
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
