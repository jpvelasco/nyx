package topology

import "testing"

func TestFingerprintRole(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		device               DeviceReport
		serving, bridge, nat bool
		want                 string
	}{
		{"edge", DeviceReport{OnPath: true, Role: RoleNatRouter}, true, false, true, "enforcer"},
		{"bridge", DeviceReport{Role: RoleBridge}, false, true, false, "observer"},
		{"no bridge evidence", DeviceReport{Role: RoleBridge}, false, false, false, "unknown"},
		{"destination-only NAT", DeviceReport{OnPath: true, Role: RoleNatRouter}, true, false, false, "unknown"},
		{"off path", DeviceReport{Role: RoleNatRouter}, true, false, true, "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			role, guide := FingerprintRole(tc.device, tc.serving, tc.bridge, tc.nat)
			if role != tc.want || (guide == "") != (role == "unknown") {
				t.Errorf("role = %q, guide = %q; want %q", role, guide, tc.want)
			}
		})
	}
}
