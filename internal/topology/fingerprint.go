package topology

// Fingerprint classifies the observed provider roles and the configured
// segments. Addresses are matched by the service and never enter the report.
type Fingerprint struct {
	Devices  []FingerprintDevice  `json:"devices"`
	Segments []FingerprintSegment `json:"segments,omitempty"`
	Warnings []string             `json:"warnings,omitempty"`
}

// FingerprintDevice contains only provider roles and aggregate evidence.
type FingerprintDevice struct {
	Provider         string `json:"provider"`
	Role             string `json:"role"`
	ManagedUpstream  string `json:"managed_upstream,omitempty"`
	InterfaceCount   int    `json:"interface_count,omitempty"`
	BridgeCount      *int   `json:"bridge_count,omitempty"`
	EnforcementRules *int   `json:"enforcement_rules,omitempty"`
	WhereToLook      string `json:"where_to_look,omitempty"`
}

// FingerprintSegment identifies a VLAN by its configured VLAN ID.
type FingerprintSegment struct {
	VLAN    int    `json:"vlan"`
	Gateway string `json:"gateway,omitempty"`
}

// FingerprintRole derives an architecture role without interpreting the
// absence of an observed upstream as proof that a provider is the edge.
func FingerprintRole(d DeviceReport, servingSegments bool, hasBridge bool, confirmedSourceNAT bool) (role, where string) {
	switch {
	case d.OnPath && d.Role == RoleNatRouter && servingSegments && confirmedSourceNAT:
		return "enforcer", "Inspect configured firewall rules, ACLs, and egress drops."
	case d.Role == RoleBridge && hasBridge:
		return "observer", "Inspect bridge members for a passive observation point."
	default:
		return "unknown", ""
	}
}
