package mcp

import "os"

// OmadaCredEnvVars and OpnsenseCredEnvVars are the canonical environment
// variable names the server reads for provider credentials, in display
// order. NewServer builds its lookup maps from them and `nyx mcp config`
// renders harness snippets from them, so both stay in sync with the
// resolution order (tool args -> env vars -> encrypted store).
var (
	OmadaCredEnvVars    = []string{"OMADA_HOST", "OMADA_CLIENT_ID", "OMADA_CLIENT_SECRET", "OMADA_SITE"}
	OpnsenseCredEnvVars = []string{"OPNSENSE_HOST", "OPNSENSE_API_KEY", "OPNSENSE_API_SECRET"}
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
