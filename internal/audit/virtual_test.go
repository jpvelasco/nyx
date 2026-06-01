package audit

import (
	"testing"
)

func TestLooksVirtual(t *testing.T) {
	tests := []struct {
		name     string
		evidence []string
		want     bool
	}{
		{
			name:     "VMware OUI 00:50:56",
			evidence: []string{"Nmap scan report for 192.168.174.254", "Host is up.", "MAC Address: 00:50:56:EE:69:AB (VMware)"},
			want:     true,
		},
		{
			name:     "VMware OUI 00:0C:29",
			evidence: []string{"MAC Address: 00:0C:29:A7:6F:AA (VMware)"},
			want:     true,
		},
		{
			name:     "VMware OUI 00:05:69",
			evidence: []string{"MAC Address: 00:05:69:11:22:33 (VMware)"},
			want:     true,
		},
		{
			name:     "VirtualBox OUI 08:00:27",
			evidence: []string{"MAC Address: 08:00:27:AB:CD:EF (VirtualBox)"},
			want:     true,
		},
		{
			name:     "Hyper-V / WSL2 OUI 00:15:5D",
			evidence: []string{"MAC Address: 00:15:5D:12:34:56 (Microsoft)"},
			want:     true,
		},
		{
			name:     "case insensitive",
			evidence: []string{"mac address: 00:50:56:aa:bb:cc (vmware)"},
			want:     true,
		},
		{
			name:     "real hardware MAC",
			evidence: []string{"MAC Address: D0:D2:B0:7B:ED:79 (Apple)"},
			want:     false,
		},
		{
			name:     "empty evidence",
			evidence: []string{},
			want:     false,
		},
		{
			name:     "no MAC line",
			evidence: []string{"Nmap done: 256 IP addresses (0 hosts up) scanned in 44s"},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := looksVirtual(tt.evidence)
			if got != tt.want {
				t.Errorf("looksVirtual(%v) = %v, want %v", tt.evidence, got, tt.want)
			}
		})
	}
}

func TestIsVirtualIfaceName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"VMware Network Adapter VMnet8", true},
		{"vEthernet (Default Switch)", true},
		{"vEthernet (WSL (Hyper-V firewall))", true},
		{"docker0", true},
		{"br-abc123", true},
		{"virbr0", true},
		{"eth0", false},
		{"Ethernet", false},
		{"en0", false},
		{"Wi-Fi", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isVirtualIfaceName(tt.name)
			if got != tt.want {
				t.Errorf("isVirtualIfaceName(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}
