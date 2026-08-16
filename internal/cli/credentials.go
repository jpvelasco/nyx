// Package cli (credentials.go) implements `nyx credentials` — managing the
// encrypted-at-rest credential store that providers fall back to when env
// vars are not set. Values are never printed by any command.
package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/jpvelasco/nyx/internal/credentials"
	"github.com/spf13/cobra"
)

var credentialsCmd = &cobra.Command{
	Use:   "credentials",
	Short: "Manage stored credentials for providers",
	Long: `Manage credentials stored in the encrypted store at
~/.nyx/credentials.json. Providers fall back to these when the matching
environment variables are not set.

Security posture: entries are AES-256-GCM encrypted before hitting disk,
but the key lives beside the store (<path>.key), so this protects against
casual/plaintext exposure — NOT against a local attacker who can read
your files, and NOT backups that include the key file. The OS keyring
integration is the planned hardening path.

Values are never printed; only entry names are listed.`,
}

var credentialsSetFlag []string

var credentialsSetCmd = &cobra.Command{
	Use:   "set <provider> [name]",
	Short: "Store a credential entry",
	Example: `  nyx credentials set omada --set host=192.168.1.1 --set username=admin --set password=secret
  nyx credentials set probe home --set host=10.0.0.5 --set username=ubuntu --set key=~/.ssh/id_ed25519`,
	Args: cobra.RangeArgs(1, 2),
	RunE: func(_ *cobra.Command, args []string) error {
		provider, name := args[0], "default"
		if len(args) == 2 {
			name = args[1]
		}
		entry := credentials.Entry{}
		for _, kv := range credentialsSetFlag {
			k, v, ok := strings.Cut(kv, "=")
			if !ok || k == "" {
				return fmt.Errorf("--set values must be key=value, got %q", kv)
			}
			entry[k] = v
		}
		if len(entry) == 0 {
			return fmt.Errorf("at least one --set key=value is required")
		}

		store, err := credentials.Open(storePath())
		if err != nil {
			return fmt.Errorf("opening credential store: %w", err)
		}
		if err := store.Set(provider, name, entry); err != nil {
			return fmt.Errorf("storing credentials: %w", err)
		}
		fmt.Printf("stored %s/%s\n", provider, name)
		return nil
	},
}

var credentialsListCmd = &cobra.Command{
	Use:   "list [provider]",
	Short: "List credential entry names (never values)",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		store, err := credentials.Open(storePath())
		if err != nil {
			return fmt.Errorf("opening credential store: %w", err)
		}

		if len(args) == 1 {
			names := store.List(args[0])
			for _, n := range names {
				fmt.Printf("%s\n", n)
			}
			return nil
		}

		providers := store.Providers()
		if len(providers) == 0 {
			fmt.Println("no credentials stored")
			return nil
		}
		for _, p := range providers {
			names := store.List(p)
			fmt.Printf("%s: %s\n", p, strings.Join(names, ", "))
		}
		return nil
	},
}

var credentialsRemoveCmd = &cobra.Command{
	Use:   "remove <provider> [name]",
	Short: "Remove a credential entry",
	Args:  cobra.RangeArgs(1, 2),
	RunE: func(_ *cobra.Command, args []string) error {
		provider, name := args[0], "default"
		if len(args) == 2 {
			name = args[1]
		}
		store, err := credentials.Open(storePath())
		if err != nil {
			return fmt.Errorf("opening credential store: %w", err)
		}
		if err := store.Remove(provider, name); err != nil {
			return fmt.Errorf("removing credentials: %w", err)
		}
		fmt.Printf("removed %s/%s\n", provider, name)
		return nil
	},
}

// credentialRequirements lists the fields each known provider must carry in
// an entry. Unknown providers only require a non-empty entry.
var credentialRequirements = map[string][]string{
	"omada":    {"host", "username", "password"},
	"opnsense": {"host", "api_key", "api_secret"},
	"probe":    {"host", "username", "key"},
}

var credentialsVerifyCmd = &cobra.Command{
	Use:   "verify [provider] [name]",
	Short: "Check that stored credentials are present and complete",
	Long: `Checks that a stored entry exists and carries the fields the
provider needs (omada: host, username, password; opnsense: host,
api_key, api_secret; probe: host, username, key). Live connectivity
verification is not performed.`,
	Args: cobra.MaximumNArgs(2),
	RunE: func(_ *cobra.Command, args []string) error {
		store, err := credentials.Open(storePath())
		if err != nil {
			return fmt.Errorf("opening credential store: %w", err)
		}

		providers := []string{}
		if len(args) >= 1 {
			providers = append(providers, args[0])
		} else {
			providers = store.Providers()
		}
		if len(providers) == 0 {
			return fmt.Errorf("no credentials stored")
		}

		failed := false
		problems := []string{}
		for _, provider := range providers {
			names := []string{"default"}
			if len(args) == 2 {
				names = []string{args[1]}
			} else if listed := store.List(provider); len(listed) > 0 {
				names = listed
			}
			for _, name := range names {
				entry, ok := store.Get(provider, name)
				if !ok {
					fmt.Printf("%s/%s: missing\n", provider, name)
					problems = append(problems, fmt.Sprintf("%s/%s: missing", provider, name))
					failed = true
					continue
				}
				missing := []string{}
				for _, field := range credentialRequirements[provider] {
					if strings.TrimSpace(entry[field]) == "" {
						missing = append(missing, field)
					}
				}
				if len(missing) > 0 {
					msg := fmt.Sprintf("%s/%s: missing required fields: %s", provider, name, strings.Join(missing, ", "))
					fmt.Printf("%s\n", msg)
					problems = append(problems, msg)
					failed = true
					continue
				}
				fmt.Printf("%s/%s: ok\n", provider, name)
			}
		}
		if failed {
			return errors.New(strings.Join(problems, "; "))
		}
		return nil
	},
}

func init() {
	credentialsSetCmd.Flags().StringArrayVar(&credentialsSetFlag, "set", nil, "Field to store as key=value (repeatable)")
	credentialsCmd.AddCommand(credentialsSetCmd)
	credentialsCmd.AddCommand(credentialsListCmd)
	credentialsCmd.AddCommand(credentialsRemoveCmd)
	credentialsCmd.AddCommand(credentialsVerifyCmd)
}

// storePath resolves the credential store location: NYX_CREDENTIALS_FILE
// env var, else the default ~/.nyx/credentials.json.
func storePath() string {
	if p := os.Getenv("NYX_CREDENTIALS_FILE"); p != "" {
		return p
	}
	return credentials.DefaultPath()
}
