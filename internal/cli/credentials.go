// Package cli (credentials.go) implements `nyx credentials` — managing the
// encrypted-at-rest credential store that providers fall back to when env
// vars are not set. Values are never printed by any command.
package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/jpvelasco/nyx/internal/credentials"
	"github.com/jpvelasco/nyx/internal/probe"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/jpvelasco/nyx/internal/storepath"
	"github.com/spf13/cobra"
	"golang.org/x/term"
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
var credentialsVerifyLive bool

// TTY / prompt seams so tests never need a real terminal.
var (
	isTerminal   = func(fd int) bool { return term.IsTerminal(fd) }
	readPassword = func(fd int) ([]byte, error) { return term.ReadPassword(fd) }
	readLine     = func(r io.Reader) (string, error) {
		s, err := bufio.NewReader(r).ReadString('\n')
		return strings.TrimRight(s, "\r\n"), err
	}
	promptIn  io.Reader = os.Stdin
	promptOut io.Writer = os.Stderr
)

var credentialsSetCmd = &cobra.Command{
	Use:   "set <provider> [name]",
	Short: "Store a credential entry",
	Long: `Store a credential entry in the encrypted store. Pass --set key=value
for each field, or omit --set on a TTY to be prompted for the provider's
required fields (secrets are entered with no echo). After store, only
"stored provider/name" is printed — never values.`,
	Example: `  nyx credentials set omada --set host=10.0.11.20 --set client_id=... --set client_secret=...
  nyx credentials set probe iot-probe --set host=10.0.60.15 --set username=ubuntu --set key=~/.ssh/id_ed25519
  nyx credentials set omada   # prompts on a TTY`,
	Args: cobra.RangeArgs(1, 2),
	RunE: func(_ *cobra.Command, args []string) error {
		provider, name := args[0], "default"
		if len(args) == 2 {
			name = args[1]
		}
		entry, err := parseSetFlags(credentialsSetFlag)
		if err != nil {
			return err
		}
		if err := fillMissingFields(provider, entry); err != nil {
			return err
		}
		if len(entry) == 0 {
			return fmt.Errorf("at least one field is required")
		}

		store, err := credentials.Open(storepath.StoreFile())
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

func parseSetFlags(kvs []string) (credentials.Entry, error) {
	entry := credentials.Entry{}
	for _, kv := range kvs {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("--set values must be key=value, got %q", kv)
		}
		entry[k] = v
	}
	return entry, nil
}

// fillMissingFields prompts on a TTY for required (and known optional)
// fields that --set did not supply. Non-TTY with missing required fields
// is an error pointing at --set.
func fillMissingFields(provider string, entry credentials.Entry) error {
	missing := credentials.MissingRequired(provider, entry)
	// A known provider with no --set also prompts for optional fields
	// (e.g. omada site). Unknown providers with no --set have nothing
	// to prompt for.
	needOptional := len(entry) == 0
	if len(missing) == 0 && !needOptional {
		return nil
	}
	if !isTerminal(int(syscall.Stdin)) {
		if len(entry) == 0 {
			return errors.New("use --set key=value or run on a TTY")
		}
		// Partial --set off a TTY is stored as-is so `verify` can
		// report the missing fields.
		return nil
	}
	fields := append([]string{}, missing...)
	if needOptional {
		fields = append(fields, credentials.OptionalFields[provider]...)
	}
	for _, field := range fields {
		if strings.TrimSpace(entry[field]) != "" {
			continue
		}
		val, err := promptField(field)
		if err != nil {
			return err
		}
		if val != "" {
			entry[field] = val
		}
	}
	return nil
}

func promptField(field string) (string, error) {
	if credentials.IsSecret(field) {
		fmt.Fprintf(promptOut, "%s: ", field)
		secret, err := readPassword(int(syscall.Stdin))
		fmt.Fprintln(promptOut)
		if err != nil {
			return "", fmt.Errorf("reading %s: %w", field, err)
		}
		return string(secret), nil
	}
	fmt.Fprintf(promptOut, "%s: ", field)
	line, err := readLine(promptIn)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("reading %s: %w", field, err)
	}
	return line, nil
}

var credentialsListCmd = &cobra.Command{
	Use:   "list [provider]",
	Short: "List credential entry names (never values)",
	Args:  cobra.MaximumNArgs(1),
	RunE: func(_ *cobra.Command, args []string) error {
		store, err := credentials.Open(storepath.StoreFile())
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
		store, err := credentials.Open(storepath.StoreFile())
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

var credentialsVerifyCmd = &cobra.Command{
	Use:   "verify [provider] [name]",
	Short: "Check that stored credentials are present and complete",
	Long: `Checks that a stored entry exists and carries the fields the
provider needs (omada: host, client_id, client_secret; opnsense: host,
api_key, api_secret; probe: host, username, key). Pass --live to also
reach the controller or probe (omada Info, opnsense Info, probe
Diagnose). Unknown providers skip the live step.`,
	Args: cobra.MaximumNArgs(2),
	RunE: func(_ *cobra.Command, args []string) error {
		store, err := credentials.Open(storepath.StoreFile())
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

		var liveCtx context.Context
		if credentialsVerifyLive {
			dur, err := parseTimeoutFlag(timeout)
			if err != nil {
				return err
			}
			if dur == 0 {
				dur = 30 * time.Second
			}
			var cancel context.CancelFunc
			liveCtx, cancel = context.WithTimeout(context.Background(), dur)
			defer cancel()
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
				missing := credentials.MissingRequired(provider, entry)
				if len(missing) > 0 {
					msg := fmt.Sprintf("%s/%s: missing required fields: %s", provider, name, strings.Join(missing, ", "))
					fmt.Printf("%s\n", msg)
					problems = append(problems, msg)
					failed = true
					continue
				}
				if credentialsVerifyLive {
					if _, known := credentials.Requirements[provider]; known {
						if err := liveVerify(liveCtx, provider, entry); err != nil {
							msg := fmt.Sprintf("%s/%s: live: %s", provider, name, sanitizeLiveError(err, entry))
							fmt.Printf("%s\n", msg)
							problems = append(problems, msg)
							failed = true
							continue
						}
						fmt.Printf("%s/%s: ok (live)\n", provider, name)
						continue
					}
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

// Live checkers are package-level seams so tests never hit the network.
var (
	liveOmada = func(ctx context.Context, opts service.OmadaOptions) error {
		_, err := service.NewOmadaService().Info(ctx, opts)
		return err
	}
	liveOpnsense = func(ctx context.Context, opts service.OpnsenseOptions) error {
		_, err := service.NewOpnsenseService().Info(ctx, opts)
		return err
	}
	liveProbe = func(ctx context.Context, p probe.Probe) error {
		return probe.Diagnose(ctx, p)
	}
)

func liveVerify(ctx context.Context, provider string, entry credentials.Entry) error {
	switch provider {
	case "omada":
		return liveOmada(ctx, service.OmadaOptions{
			Host:         entry["host"],
			ClientID:     entry["client_id"],
			ClientSecret: entry["client_secret"],
			Site:         entry["site"],
		})
	case "opnsense":
		return liveOpnsense(ctx, service.OpnsenseOptions{
			Host:      entry["host"],
			APIKey:    entry["api_key"],
			APISecret: entry["api_secret"],
		})
	case "probe":
		return liveProbe(ctx, probe.Probe{
			Name: "verify",
			Host: entry["host"],
			User: entry["username"],
			Key:  entry["key"],
		})
	default:
		return nil
	}
}

// sanitizeLiveError strips stored secret values from a live-check error
// so a controller/transport message cannot echo them back.
func sanitizeLiveError(err error, entry credentials.Entry) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	for field, val := range entry {
		if credentials.IsSecret(field) && val != "" {
			msg = strings.ReplaceAll(msg, val, "[redacted]")
		}
	}
	return msg
}

func init() {
	credentialsSetCmd.Flags().StringArrayVar(&credentialsSetFlag, "set", nil, "Field to store as key=value (repeatable)")
	credentialsVerifyCmd.Flags().BoolVar(&credentialsVerifyLive, "live", false, "Reach the controller or probe instead of checking field presence only")
	credentialsCmd.AddCommand(credentialsSetCmd)
	credentialsCmd.AddCommand(credentialsListCmd)
	credentialsCmd.AddCommand(credentialsRemoveCmd)
	credentialsCmd.AddCommand(credentialsVerifyCmd)
}
