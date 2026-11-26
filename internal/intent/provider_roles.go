package intent

// ProviderLookup reports the roles a compiled adapter can serve, without accessing a controller.
// The lookup is injected by the caller so the intent package has no provider dependency.
type ProviderLookup func(provider, role string) bool

const (
	RoleEdge             = "edge"
	RoleObserver         = "observer"
	RoleBidirectionalACL = "bidirectional_acl"
)

// BuiltinProviderRole describes the historical v1 spec semantics for standalone parsing.
func BuiltinProviderRole(provider, role string) bool {
	switch role {
	case RoleEdge, RoleObserver, "acl_drift", "acl_check", "nat_check":
		return provider == "omada" || provider == "opnsense"
	case RoleBidirectionalACL, "wlan_schedule_liveness":
		return provider == "omada"
	default:
		return false
	}
}
