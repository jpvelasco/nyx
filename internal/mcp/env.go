package mcp

import (
	"os"

	"github.com/jpvelasco/nyx/internal/credentials"
)

// OmadaCredEnvVars and OpnsenseCredEnvVars are the canonical environment
// variable names the server reads for provider credentials, in display
// order. NewServer builds its lookup maps from them and `nyx mcp config`
// renders harness snippets from them, so both stay in sync with the
// resolution order (tool args -> env vars -> encrypted store).
var (
	OmadaCredEnvVars    = credentialEnvNames("omada")
	OpnsenseCredEnvVars = credentialEnvNames("opnsense")
)

// credEnvFrom builds an env-var lookup map for the given names. A missing
// key at call time leaves that credential layer empty.
func credEnvFrom(names []string) map[string]func(string) string {
	envs := make(map[string]func(string) string, len(names))
	for _, name := range names {
		envs[name] = os.Getenv
	}
	return envs
}

func credentialEnvNames(provider string) []string {
	var names []string
	for _, f := range credentials.FieldsFor(provider) {
		if f.Env != "" {
			names = append(names, f.Env)
		}
	}
	return names
}
