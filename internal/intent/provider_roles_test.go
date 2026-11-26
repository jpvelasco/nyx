package intent

import "testing"

func TestOfflineProviderRoles(t *testing.T) {
	catalog := ProviderLookup(func(provider, role string) bool {
		return provider == "synthetic" && role == RoleObserver || BuiltinProviderRole(provider, role)
	})
	ok := []byte("version: 1\nsite: example\nnetworks:\n- {name: trusted, cidr: 10.0.10.0/24, edge: opnsense, observer: synthetic}\n")
	if _, err := catalog.ParseSpec(ok); err != nil {
		t.Fatal(err)
	}
	for _, assertion := range []string{"{type: acl_check, policy: trusted, expect: enforced, provider: synthetic}", "{type: nat_check, nat_mode: disabled, provider: synthetic}", "{type: acl_drift, provider: synthetic}", "{type: wlan_schedule_liveness, provider: synthetic}"} {
		if _, err := catalog.ParseSpec(append(append([]byte(nil), ok...), []byte("assertions:\n- "+assertion+"\n")...)); err == nil {
			t.Errorf("unexpectedly accepted %s", assertion)
		}
	}
}
