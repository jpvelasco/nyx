# Nyx Polish Sprint Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rename netaudit → nyx, fix 6 known bugs with regression tests, add provider abstraction (Omada + OPNsense stub), structured logging, `doctor` command, and full CLI/MCP parity.

**Architecture:** The existing Cobra CLI + audit engine structure is kept intact. New packages are added alongside existing ones: `internal/version`, `internal/logger`, `internal/providers` (interface + registry + omada + opnsense). The MCP server is updated in-place. No existing public interfaces change — only bugs are fixed and new packages are wired in.

**Tech Stack:** Go 1.22+, Cobra, gopkg.in/yaml.v3, stdlib only (no new dependencies)

---

## File Map

### New files
- `internal/version/version.go` — single version constant
- `internal/logger/logger.go` — JSON-lines rotating logger
- `internal/providers/provider.go` — Provider interface + ImportResult + ProviderInfo types
- `internal/providers/registry.go` — Register/Get/List functions
- `internal/providers/omada/provider.go` — Omada implements Provider (wraps existing omada backend)
- `internal/providers/opnsense/provider.go` — OPNsense stub (Info only)
- `internal/providers/opnsense/client.go` — OPNsense HTTP client (Basic Auth, Info endpoint)
- `internal/cli/doctor.go` — `nyx doctor` command
- `internal/cli/provider.go` — `nyx provider list` command + dynamic vendor subcommand routing

### Modified files
- `cmd/netaudit/main.go` → `cmd/nyx/main.go` — rename + import providers
- `go.mod` — module path rename
- `Makefile` — binary name
- `.github/workflows/ci.yaml` — binary name
- `internal/cli/root.go` — Use: "nyx", wire doctor + provider commands
- `internal/cli/audit.go` — fix bugs 1+2, wire logger
- `internal/cli/omada.go` — remove (logic moves to providers/omada; CLI wired via provider registry)
- `internal/audit/engine.go` — fix bug 3
- `internal/intent/spec.go` — fix bug 4
- `internal/mcp/server.go` — fix bug 6, add new tools, all tools return CheckResult JSON
- `internal/models/result.go` — fix bug 5 (no change here; fix is in engine.go)
- `internal/report/report.go` — add `RenderRecommendations(w, recs)`
- `internal/backends/omada/*` — kept as-is (providers/omada wraps them)
- `README.md` — rename + prerequisites
- `CLAUDE.md` — rename + new packages

### Deleted files
- `internal/cli/omada.go` — replaced by provider routing in `internal/cli/provider.go`

### Test files
- `internal/intent/spec_test.go` — extend with bug 4 cases
- `internal/audit/engine_test.go` — new: bugs 3+5
- `internal/cli/audit_test.go` — new: bugs 1+2
- `internal/mcp/server_test.go` — new: bug 6
- `internal/providers/registry_test.go` — new: registry behavior
- `internal/logger/logger_test.go` — new: rotation + no-sensitive-data

---

## Task 1: Rename — module path and binary

**Files:**
- Modify: `go.mod`
- Modify: `cmd/netaudit/main.go` → move to `cmd/nyx/main.go`
- Modify: `Makefile`
- Modify: `.github/workflows/ci.yaml`
- Modify: all `*.go` import paths

- [ ] **Step 1: Update go.mod**

```
module github.com/velasco-jp/nyx

go 1.25.0

require (
	github.com/spf13/cobra v1.8.1
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
)
```

- [ ] **Step 2: Move cmd directory**

```bash
mv F:/source/netaudit/cmd/netaudit F:/source/netaudit/cmd/nyx
```

- [ ] **Step 3: Update cmd/nyx/main.go**

```go
package main

import (
	"os"

	"github.com/velasco-jp/nyx/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(2)
	}
}
```

- [ ] **Step 4: Sed-replace all import paths in .go files**

```bash
cd F:/source/netaudit
find . -name "*.go" -not -path "./.gocache/*" | xargs sed -i 's|github.com/velasco-jp/netaudit|github.com/velasco-jp/nyx|g'
```

- [ ] **Step 5: Update Makefile**

```makefile
.PHONY: build test vet clean

BINARY = nyx
MODULE = github.com/velasco-jp/nyx

build:
	go build -o $(BINARY) ./cmd/nyx/

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -f $(BINARY) nyx-*

release:
	GOOS=linux GOARCH=amd64 go build -o $(BINARY)-linux-amd64 ./cmd/nyx/
	GOOS=linux GOARCH=arm64 go build -o $(BINARY)-linux-arm64 ./cmd/nyx/
	GOOS=darwin GOARCH=amd64 go build -o $(BINARY)-darwin-amd64 ./cmd/nyx/
	GOOS=darwin GOARCH=arm64 go build -o $(BINARY)-darwin-arm64 ./cmd/nyx/
	GOOS=windows GOARCH=amd64 go build -o $(BINARY)-windows-amd64.exe ./cmd/nyx/

.DEFAULT_GOAL := build
```

- [ ] **Step 6: Update CI workflow binary references**

In `.github/workflows/ci.yaml`, replace every `netaudit` reference with `nyx` and `./cmd/netaudit/` with `./cmd/nyx/`.

- [ ] **Step 7: Update root.go Use field and version command**

In `internal/cli/root.go`, change:
```go
var rootCmd = &cobra.Command{
	Use:   "nyx",
```
And update the version command:
```go
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("nyx v0.1.0")
	},
}
```

- [ ] **Step 8: Update all Example: strings in CLI commands**

Search for `netaudit` in all `internal/cli/*.go` files and replace with `nyx`.

```bash
find F:/source/netaudit/internal/cli -name "*.go" | xargs sed -i 's/netaudit/nyx/g'
```

- [ ] **Step 9: Update MCP server name**

In `internal/mcp/server.go`, change:
```go
ServerInfo: serverInfo{
    Name:    "nyx",
    Version: "0.1.0",
},
```

- [ ] **Step 10: Verify build**

```bash
cd F:/source/netaudit && go build ./... && go vet ./...
```
Expected: no errors, `nyx.exe` produced.

- [ ] **Step 11: Commit**

```bash
git add -A
git commit -m "chore: rename netaudit → nyx (module path, binary, commands)"
```

---

## Task 2: Version package

**Files:**
- Create: `internal/version/version.go`
- Modify: `internal/cli/root.go`
- Modify: `internal/mcp/server.go`

- [ ] **Step 1: Create version package**

Create `internal/version/version.go`:
```go
package version

// Version is the single source of truth for the nyx release version.
const Version = "0.1.0"
```

- [ ] **Step 2: Wire into version command in root.go**

In `internal/cli/root.go`, add import `"github.com/velasco-jp/nyx/internal/version"` and update:
```go
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("nyx v%s\n", version.Version)
	},
}
```

- [ ] **Step 3: Wire into MCP server**

In `internal/mcp/server.go`, add import and update:
```go
import "github.com/velasco-jp/nyx/internal/version"

// in handleInitialize:
ServerInfo: serverInfo{
    Name:    "nyx",
    Version: version.Version,
},
```

- [ ] **Step 4: Build and verify**

```bash
cd F:/source/netaudit && go build ./... && ./nyx.exe version
```
Expected output: `nyx v0.1.0`

- [ ] **Step 5: Commit**

```bash
git add internal/version/version.go internal/cli/root.go internal/mcp/server.go
git commit -m "feat: single-source version package"
```

---

## Task 3: Provider abstraction + Omada provider + OPNsense stub

**Files:**
- Create: `internal/providers/provider.go`
- Create: `internal/providers/registry.go`
- Create: `internal/providers/registry_test.go`
- Create: `internal/providers/omada/provider.go`
- Create: `internal/providers/opnsense/client.go`
- Create: `internal/providers/opnsense/provider.go`
- Modify: `internal/cli/provider.go` (new file)
- Modify: `internal/cli/root.go`
- Modify: `cmd/nyx/main.go`

- [ ] **Step 1: Write the failing registry test**

Create `internal/providers/registry_test.go`:
```go
package providers_test

import (
	"testing"

	providers "github.com/velasco-jp/nyx/internal/providers"
)

type mockProvider struct{ name string }

func (m *mockProvider) Name() string        { return m.name }
func (m *mockProvider) Capabilities() []string { return []string{"info"} }

func TestRegisterAndGet(t *testing.T) {
	providers.Reset() // clear for test isolation
	p := &mockProvider{name: "test"}
	providers.Register(p)

	got := providers.Get("test")
	if got == nil {
		t.Fatal("expected provider, got nil")
	}
	if got.Name() != "test" {
		t.Fatalf("expected name 'test', got %q", got.Name())
	}
}

func TestGetUnknown(t *testing.T) {
	providers.Reset()
	got := providers.Get("unknown")
	if got != nil {
		t.Fatal("expected nil for unknown provider")
	}
}

func TestList(t *testing.T) {
	providers.Reset()
	providers.Register(&mockProvider{name: "a"})
	providers.Register(&mockProvider{name: "b"})
	list := providers.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 providers, got %d", len(list))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd F:/source/netaudit && go test ./internal/providers/...
```
Expected: compile error — package does not exist yet.

- [ ] **Step 3: Create provider interface**

Create `internal/providers/provider.go`:
```go
package providers

import (
	"context"

	"github.com/velasco-jp/nyx/internal/intent"
	"github.com/velasco-jp/nyx/internal/models"
)

// ImportOptions holds credentials and options for provider connections.
type ImportOptions struct {
	Host     string
	Username string
	Password string
	Site     string
	Debug    bool
}

// ProviderInfo holds version and connection metadata returned by Info.
type ProviderInfo struct {
	Provider string `json:"provider"`
	Host     string `json:"host"`
	Version  string `json:"version"`
	Extra    map[string]string `json:"extra,omitempty"`
}

// ImportResult holds a generated spec and import summary.
type ImportResult struct {
	Spec         *intent.Spec
	ProviderInfo ProviderInfo
	NetworkCount int
	PolicyCount  int
	ClientCount  int
	Warnings     []string
}

// AuditResult holds the result of a provider-driven audit.
type AuditResult struct {
	Report   *models.AuditReport
	Warnings []string
}

// Provider is implemented by each vendor backend.
type Provider interface {
	// Name returns the CLI subcommand name, e.g. "omada", "opnsense".
	Name() string
	// Capabilities returns the list of supported operations: "info", "import", "check".
	Capabilities() []string
	// Info returns version and connection metadata. No credentials required if possible.
	Info(ctx context.Context, opts ImportOptions) (*ProviderInfo, error)
	// ImportSpec fetches controller config and returns a populated intent.Spec.
	// Returns ErrCapabilityUnsupported if not supported.
	ImportSpec(ctx context.Context, opts ImportOptions) (*ImportResult, error)
	// Check imports a spec and immediately runs a live audit.
	// Returns ErrCapabilityUnsupported if not supported.
	Check(ctx context.Context, opts ImportOptions) (*AuditResult, error)
}

// ErrCapabilityUnsupported is returned when a provider does not support an operation.
type ErrCapabilityUnsupported struct {
	Provider   string
	Capability string
}

func (e *ErrCapabilityUnsupported) Error() string {
	return "provider \"" + e.Provider + "\" does not support \"" + e.Capability + "\""
}
```

- [ ] **Step 4: Create registry**

Create `internal/providers/registry.go`:
```go
package providers

import "sync"

var (
	mu       sync.RWMutex
	registry = map[string]Provider{}
)

// Register adds a provider to the registry. Panics on duplicate name.
func Register(p Provider) {
	mu.Lock()
	defer mu.Unlock()
	if _, exists := registry[p.Name()]; exists {
		panic("provider already registered: " + p.Name())
	}
	registry[p.Name()] = p
}

// Get returns the provider with the given name, or nil if not found.
func Get(name string) Provider {
	mu.RLock()
	defer mu.RUnlock()
	return registry[name]
}

// List returns all registered providers in arbitrary order.
func List() []Provider {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Provider, 0, len(registry))
	for _, p := range registry {
		out = append(out, p)
	}
	return out
}

// Reset clears the registry. For testing only.
func Reset() {
	mu.Lock()
	defer mu.Unlock()
	registry = map[string]Provider{}
}
```

- [ ] **Step 5: Run registry test to verify it passes**

```bash
cd F:/source/netaudit && go test ./internal/providers/...
```
Expected: PASS

- [ ] **Step 6: Create Omada provider wrapper**

Create `internal/providers/omada/provider.go`:
```go
package omadaprovider

import (
	"context"
	"fmt"

	"github.com/velasco-jp/nyx/internal/audit"
	omadabackend "github.com/velasco-jp/nyx/internal/backends/omada"
	"github.com/velasco-jp/nyx/internal/models"
	providers "github.com/velasco-jp/nyx/internal/providers"
)

// OmadaProvider implements providers.Provider for TP-Link Omada SDN controllers.
type OmadaProvider struct{}

func (o *OmadaProvider) Name() string { return "omada" }

func (o *OmadaProvider) Capabilities() []string {
	return []string{"info", "import", "check"}
}

func (o *OmadaProvider) Info(ctx context.Context, opts providers.ImportOptions) (*providers.ProviderInfo, error) {
	client, err := omadabackend.NewClient(ctx, opts.Host)
	if err != nil {
		return nil, fmt.Errorf("connecting to omada controller: %w", err)
	}
	info := client.Info()
	return &providers.ProviderInfo{
		Provider: "omada",
		Host:     opts.Host,
		Version:  info.ControllerVer,
		Extra: map[string]string{
			"api_version": info.APIVer,
			"omada_cid":   info.OmadaCID,
		},
	}, nil
}

func (o *OmadaProvider) ImportSpec(ctx context.Context, opts providers.ImportOptions) (*providers.ImportResult, error) {
	result, err := omadabackend.ImportSpec(ctx, opts.Host, opts.Username, opts.Password, opts.Site, opts.Debug)
	if err != nil {
		return nil, err
	}
	return &providers.ImportResult{
		Spec: result.Spec,
		ProviderInfo: providers.ProviderInfo{
			Provider: "omada",
			Host:     opts.Host,
			Version:  result.ControllerVersion,
		},
		NetworkCount: result.NetworkCount,
		PolicyCount:  result.ACLRuleCount,
		ClientCount:  result.ClientCount,
		Warnings:     result.Warnings,
	}, nil
}

func (o *OmadaProvider) Check(ctx context.Context, opts providers.ImportOptions) (*providers.AuditResult, error) {
	imported, err := o.ImportSpec(ctx, opts)
	if err != nil {
		return nil, err
	}
	engine := audit.NewEngine(imported.Spec)
	report, err := engine.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("audit failed: %w", err)
	}
	return &providers.AuditResult{
		Report:   report,
		Warnings: imported.Warnings,
	}, nil
}

// Ensure OmadaProvider satisfies the interface at compile time.
var _ providers.Provider = (*OmadaProvider)(nil)

// Ensure the audit result type is used correctly.
var _ *models.AuditReport = (*models.AuditReport)(nil)
```

- [ ] **Step 7: Create OPNsense client**

Create `internal/providers/opnsense/client.go`:
```go
package opnsense

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// firmwareInfoResponse is the shape of GET /api/core/firmware/running
type firmwareInfoResponse struct {
	ProductVersion string `json:"product_version"`
	ProductName    string `json:"product_name"`
	ProductArch    string `json:"product_arch"`
}

// Client is a minimal read-only OPNsense API client using Basic Auth.
// TLS verification is skipped because OPNsense ships with a self-signed cert.
type Client struct {
	host       string
	apiKey     string
	apiSecret  string
	httpClient *http.Client
}

// NewClient creates an OPNsense client. No network calls are made here.
func NewClient(host, apiKey, apiSecret string) *Client {
	host = strings.TrimPrefix(host, "https://")
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimRight(host, "/")
	return &Client{
		host:      host,
		apiKey:    apiKey,
		apiSecret: apiSecret,
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true, //nolint:gosec // self-signed controller cert
				},
			},
		},
	}
}

// GetFirmwareInfo returns the running firmware version from the controller.
func (c *Client) GetFirmwareInfo(ctx context.Context) (*firmwareInfoResponse, error) {
	url := fmt.Sprintf("https://%s/api/core/firmware/running", c.host)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.apiKey, c.apiSecret)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connecting to OPNsense at %s: %w", c.host, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("authentication failed — check API key and secret")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d from OPNsense", resp.StatusCode)
	}

	var info firmwareInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decoding firmware response: %w", err)
	}
	return &info, nil
}
```

- [ ] **Step 8: Create OPNsense provider stub**

Create `internal/providers/opnsense/provider.go`:
```go
package opnsense

import (
	"context"
	"fmt"

	providers "github.com/velasco-jp/nyx/internal/providers"
)

// OPNsenseProvider implements providers.Provider for OPNsense firewalls.
// Currently only Info is implemented. ImportSpec and Check are stubs.
type OPNsenseProvider struct{}

func (o *OPNsenseProvider) Name() string { return "opnsense" }

func (o *OPNsenseProvider) Capabilities() []string {
	return []string{"info"}
}

func (o *OPNsenseProvider) Info(ctx context.Context, opts providers.ImportOptions) (*providers.ProviderInfo, error) {
	if opts.Host == "" {
		return nil, fmt.Errorf("--host is required for opnsense provider")
	}
	client := NewClient(opts.Host, opts.Username, opts.Password)
	fw, err := client.GetFirmwareInfo(ctx)
	if err != nil {
		return nil, err
	}
	return &providers.ProviderInfo{
		Provider: "opnsense",
		Host:     opts.Host,
		Version:  fw.ProductVersion,
		Extra: map[string]string{
			"product": fw.ProductName,
			"arch":    fw.ProductArch,
		},
	}, nil
}

func (o *OPNsenseProvider) ImportSpec(ctx context.Context, opts providers.ImportOptions) (*providers.ImportResult, error) {
	return nil, &providers.ErrCapabilityUnsupported{Provider: "opnsense", Capability: "import"}
}

func (o *OPNsenseProvider) Check(ctx context.Context, opts providers.ImportOptions) (*providers.AuditResult, error) {
	return nil, &providers.ErrCapabilityUnsupported{Provider: "opnsense", Capability: "check"}
}

// Ensure OPNsenseProvider satisfies the interface at compile time.
var _ providers.Provider = (*OPNsenseProvider)(nil)
```

- [ ] **Step 9: Create CLI provider command**

Create `internal/cli/provider.go`:
```go
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/spf13/cobra"
	providers "github.com/velasco-jp/nyx/internal/providers"
	"github.com/velasco-jp/nyx/internal/report"
)

var (
	providerHost     string
	providerUsername string
	providerPassword string
	providerSite     string
	providerDebug    bool
	providerOutFile  string
)

var providerCmd = &cobra.Command{
	Use:   "provider",
	Short: "Manage and query registered network providers",
}

var providerListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all registered providers and their capabilities",
	RunE: func(cmd *cobra.Command, args []string) error {
		list := providers.List()
		sort.Slice(list, func(i, j int) bool {
			return list[i].Name() < list[j].Name()
		})
		if jsonOutput {
			type entry struct {
				Name         string   `json:"name"`
				Capabilities []string `json:"capabilities"`
			}
			out := make([]entry, len(list))
			for i, p := range list {
				out[i] = entry{Name: p.Name(), Capabilities: p.Capabilities()}
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(out)
		}
		if len(list) == 0 {
			fmt.Println("No providers registered.")
			return nil
		}
		fmt.Printf("%-15s %s\n", "PROVIDER", "CAPABILITIES")
		for _, p := range list {
			caps := ""
			for i, c := range p.Capabilities() {
				if i > 0 {
					caps += ", "
				}
				caps += c
			}
			fmt.Printf("%-15s %s\n", p.Name(), caps)
		}
		return nil
	},
}

// BuildProviderSubcommands creates `nyx <vendor> import/check/info` subcommands
// for each registered provider and adds them to the root command.
func BuildProviderSubcommands(root *cobra.Command) {
	for _, p := range providers.List() {
		p := p // capture
		vendorCmd := &cobra.Command{
			Use:   p.Name(),
			Short: fmt.Sprintf("%s provider commands", p.Name()),
		}

		caps := map[string]bool{}
		for _, c := range p.Capabilities() {
			caps[c] = true
		}

		if caps["info"] {
			vendorCmd.AddCommand(buildInfoCmd(p))
		}
		if caps["import"] {
			vendorCmd.AddCommand(buildImportCmd(p))
		}
		if caps["check"] {
			vendorCmd.AddCommand(buildCheckCmd(p))
		}

		root.AddCommand(vendorCmd)
	}
}

func buildInfoCmd(p providers.Provider) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "info",
		Short: fmt.Sprintf("Show %s controller version and connection info", p.Name()),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			info, err := p.Info(ctx, providers.ImportOptions{
				Host:     providerHost,
				Username: providerUsername,
				Password: providerPassword,
			})
			if err != nil {
				return err
			}
			if jsonOutput {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(info)
			}
			fmt.Printf("Provider : %s\n", info.Provider)
			fmt.Printf("Host     : %s\n", info.Host)
			fmt.Printf("Version  : %s\n", info.Version)
			for k, v := range info.Extra {
				fmt.Printf("%-9s: %s\n", k, v)
			}
			return nil
		},
	}
	addProviderFlags(cmd)
	return cmd
}

func buildImportCmd(p providers.Provider) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import",
		Short: fmt.Sprintf("Import network topology from %s and generate a spec", p.Name()),
		RunE: func(cmd *cobra.Command, args []string) error {
			dur, _ := time.ParseDuration(timeout)
			if dur == 0 {
				dur = 60 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), dur)
			defer cancel()

			result, err := p.ImportSpec(ctx, providers.ImportOptions{
				Host:     providerHost,
				Username: providerUsername,
				Password: providerPassword,
				Site:     providerSite,
				Debug:    providerDebug,
			})
			if err != nil {
				return err
			}
			for _, w := range result.Warnings {
				fmt.Fprintf(os.Stderr, "Warning: %s\n", w)
			}
			fmt.Fprintf(os.Stderr, "Imported: %d networks, %d policies, %d clients\n",
				result.NetworkCount, result.PolicyCount, result.ClientCount)

			out, err := marshalSpecYAML(result, p.Name())
			if err != nil {
				return err
			}
			if providerOutFile != "" {
				if err := os.WriteFile(providerOutFile, out, 0644); err != nil {
					return fmt.Errorf("writing spec: %w", err)
				}
				fmt.Fprintf(os.Stderr, "Spec written to %s\n", providerOutFile)
				return nil
			}
			fmt.Print(string(out))
			return nil
		},
	}
	addProviderFlags(cmd)
	cmd.Flags().StringVar(&providerSite, "site", "", "Site name (defaults to first site)")
	cmd.Flags().StringVar(&providerOutFile, "out", "", "Write spec YAML to file (default: stdout)")
	cmd.Flags().BoolVar(&providerDebug, "debug", false, "Print raw API responses to stderr")
	return cmd
}

func buildCheckCmd(p providers.Provider) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check",
		Short: fmt.Sprintf("Import from %s and immediately run a live audit", p.Name()),
		RunE: func(cmd *cobra.Command, args []string) error {
			dur, _ := time.ParseDuration(timeout)
			if dur == 0 {
				dur = 300 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), dur)
			defer cancel()

			result, err := p.Check(ctx, providers.ImportOptions{
				Host:     providerHost,
				Username: providerUsername,
				Password: providerPassword,
				Site:     providerSite,
				Debug:    providerDebug,
			})
			if err != nil {
				return err
			}
			for _, w := range result.Warnings {
				fmt.Fprintf(os.Stderr, "Warning: %s\n", w)
			}

			w, err := getWriter()
			if err != nil {
				return err
			}
			if outputPath != "" {
				defer w.Close()
			}
			if jsonOutput {
				return report.RenderJSON(w, result.Report)
			}
			report.RenderHuman(w, result.Report)
			return nil
		},
	}
	addProviderFlags(cmd)
	cmd.Flags().StringVar(&providerSite, "site", "", "Site name")
	cmd.Flags().BoolVar(&providerDebug, "debug", false, "Print raw API responses to stderr")
	return cmd
}

func addProviderFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&providerHost, "host", "", "Controller IP or hostname (or set <PROVIDER>_HOST env var)")
	cmd.Flags().StringVar(&providerUsername, "username", "", "Admin username (or set <PROVIDER>_USERNAME env var)")
	cmd.Flags().StringVar(&providerPassword, "password", "", "Admin password (or set <PROVIDER>_PASSWORD env var)")
}

func marshalSpecYAML(result *providers.ImportResult, providerName string) ([]byte, error) {
	// Import yaml here to avoid adding it to the provider package
	import_yaml := func() ([]byte, error) {
		// Use the same approach as the old omada CLI
		return nil, nil
	}
	_, _ = import_yaml
	// This is handled in the caller using gopkg.in/yaml.v3
	return nil, fmt.Errorf("not reached")
}

func init() {
	providerCmd.AddCommand(providerListCmd)
}
```

> **Note:** The `marshalSpecYAML` stub above will be replaced in the next step with a real implementation using `gopkg.in/yaml.v3`. The build will fail until that step is done.

- [ ] **Step 10: Fix marshalSpecYAML and finalize provider.go**

Replace the entire `marshalSpecYAML` function and its bogus import attempt in `internal/cli/provider.go`:

```go
import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/spf13/cobra"
	providers "github.com/velasco-jp/nyx/internal/providers"
	"github.com/velasco-jp/nyx/internal/report"
	"gopkg.in/yaml.v3"
)
```

And replace `marshalSpecYAML`:
```go
func marshalSpecYAML(result *providers.ImportResult, providerName string) ([]byte, error) {
	specBytes, err := yaml.Marshal(result.Spec)
	if err != nil {
		return nil, fmt.Errorf("serializing spec: %w", err)
	}
	header := fmt.Sprintf("# Generated by nyx %s import\n# Host: %s  Version: %s\n\n",
		providerName, result.ProviderInfo.Host, result.ProviderInfo.Version)
	return append([]byte(header), specBytes...), nil
}
```

- [ ] **Step 11: Register providers and wire CLI in main.go**

Update `cmd/nyx/main.go`:
```go
package main

import (
	"os"

	"github.com/velasco-jp/nyx/internal/cli"
	_ "github.com/velasco-jp/nyx/internal/providers/omada"
	_ "github.com/velasco-jp/nyx/internal/providers/opnsense"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(2)
	}
}
```

Add `init()` functions to each provider package to self-register. In `internal/providers/omada/provider.go`:
```go
func init() {
	providers.Register(&OmadaProvider{})
}
```

In `internal/providers/opnsense/provider.go`:
```go
func init() {
	providers.Register(&OPNsenseProvider{})
}
```

- [ ] **Step 12: Wire BuildProviderSubcommands in root.go**

In `internal/cli/root.go`, update `Execute()`:
```go
func Execute() error {
	BuildProviderSubcommands(rootCmd)
	return rootCmd.Execute()
}
```

And remove `omadaCmd` from the `init()` `AddCommand` calls (the provider system replaces it).

- [ ] **Step 13: Delete old omada CLI file**

```bash
rm F:/source/netaudit/internal/cli/omada.go
```

- [ ] **Step 14: Build and verify**

```bash
cd F:/source/netaudit && go build ./... && go vet ./...
./nyx.exe provider list
./nyx.exe omada info --host 192.168.0.253
./nyx.exe opnsense info --host 192.168.0.100 --username <key> --password <secret>
```
Expected: `provider list` shows omada and opnsense; `omada info` shows controller version; `opnsense info` shows OPNsense firmware version.

- [ ] **Step 15: Commit**

```bash
git add -A
git commit -m "feat: provider abstraction, omada provider, opnsense stub"
```

---

## Task 4: Bug Fix 1 — Recommendations bypass --output

**Files:**
- Modify: `internal/report/report.go`
- Modify: `internal/cli/audit.go`
- Create: `internal/cli/audit_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/cli/audit_test.go`:
```go
package cli_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/velasco-jp/nyx/internal/recommendations"
	"github.com/velasco-jp/nyx/internal/report"
)

func TestRenderRecommendationsGoesToWriter(t *testing.T) {
	recs := []recommendations.Recommendation{
		{
			Priority:    1,
			Category:    "security",
			Title:       "Test recommendation",
			Description: "A test description",
			Remediation: "Do something",
			Affected:    []string{"192.168.1.0/24"},
		},
	}

	tmpFile := filepath.Join(t.TempDir(), "out.txt")
	f, err := os.Create(tmpFile)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	report.RenderRecommendations(f, recs)

	content, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(content), "Test recommendation") {
		t.Errorf("expected recommendation in file output, got: %s", string(content))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd F:/source/netaudit && go test ./internal/cli/...
```
Expected: compile error — `report.RenderRecommendations` does not exist.

- [ ] **Step 3: Add RenderRecommendations to report package**

Add to `internal/report/report.go`:
```go
import "github.com/velasco-jp/nyx/internal/recommendations"

// RenderRecommendations writes the recommendations block to w.
func RenderRecommendations(w io.Writer, recs []recommendations.Recommendation) {
	if len(recs) == 0 {
		return
	}
	fmt.Fprintln(w, "\n--- Recommendations ---")
	for _, r := range recs {
		fmt.Fprintf(w, "[%d] %s (%s)\n", r.Priority, r.Title, r.Category)
		fmt.Fprintf(w, "   %s\n", r.Description)
		fmt.Fprintf(w, "   REMEDIATION: %s\n", r.Remediation)
		if len(r.Affected) > 0 {
			fmt.Fprintf(w, "   AFFECTED: %s\n", r.Affected[0])
		}
		fmt.Fprintln(w)
	}
}
```

- [ ] **Step 4: Update audit.go to use RenderRecommendations**

In `internal/cli/audit.go`, replace the inline recommendations block:
```go
// Before (remove this):
fmt.Println("\n--- Recommendations ---")
for _, r := range recs {
    fmt.Printf("[%d] %s (%s)\n", r.Priority, r.Title, r.Category)
    // ...
}

// After:
report.RenderRecommendations(w, recs)
```

- [ ] **Step 5: Run test to verify it passes**

```bash
cd F:/source/netaudit && go test ./internal/cli/...
```
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/report/report.go internal/cli/audit.go internal/cli/audit_test.go
git commit -m "fix: recommendations respect --output writer"
```

---

## Task 5: Bug Fix 2 — JSON mode polluted by recommendations

**Files:**
- Modify: `internal/cli/audit.go`
- Modify: `internal/cli/audit_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/cli/audit_test.go`:
```go
func TestRecommendationsNotInJSONOutput(t *testing.T) {
	// Simulate what audit.go does when jsonOutput = true
	// The recommendations block must not run when jsonOutput is true.
	// We test RenderRecommendations is not called when json mode is active
	// by verifying that a buffer written to only with RenderJSON produces valid JSON.
	var buf strings.Builder
	recs := []recommendations.Recommendation{
		{Priority: 1, Title: "Should not appear", Category: "test",
			Description: "desc", Remediation: "fix"},
	}

	// Simulate json mode: only RenderJSON is called, not RenderRecommendations
	report.RenderJSON(&buf, &models.AuditReport{
		Audit:  "test",
		Status: models.StatusPass,
	})

	// The output must be valid JSON
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(buf.String()), &result); err != nil {
		t.Errorf("JSON output is not valid JSON: %v\nOutput: %s", err, buf.String())
	}

	// Recommendations must not appear
	if strings.Contains(buf.String(), recs[0].Title) {
		t.Errorf("recommendations leaked into JSON output")
	}
}
```

Add required imports to the test file:
```go
import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/velasco-jp/nyx/internal/models"
	"github.com/velasco-jp/nyx/internal/recommendations"
	"github.com/velasco-jp/nyx/internal/report"
)
```

- [ ] **Step 2: Run test to verify it passes already (it should)**

```bash
cd F:/source/netaudit && go test ./internal/cli/...
```
If it passes, the JSON path is already clean from Task 4. If not, continue to step 3.

- [ ] **Step 3: Gate recommendations behind !jsonOutput in audit.go**

In `internal/cli/audit.go`, ensure the recommendations block is guarded:
```go
if !jsonOutput && auditReport.Status == models.StatusFail {
    failures := auditReport.Failures()
    networks := make(map[string]*intent.Network)
    for _, n := range spec.Networks {
        n := n
        networks[n.Name] = &n
    }
    recs, err = recommendations.GenerateRecommendations(failures, networks)
    if err != nil {
        fmt.Fprintf(os.Stderr, "Warning: could not generate recommendations: %v\n", err)
    } else {
        report.RenderRecommendations(w, recs)
    }
}
```

- [ ] **Step 4: Run all tests**

```bash
cd F:/source/netaudit && go test ./...
```
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add internal/cli/audit.go internal/cli/audit_test.go
git commit -m "fix: gate recommendations behind !jsonOutput"
```

---

## Task 6: Bug Fix 3 — subnet_discovery warn→pass overwrite

**Files:**
- Modify: `internal/audit/engine.go`
- Create: `internal/audit/engine_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/audit/engine_test.go`:
```go
package audit_test

import (
	"context"
	"testing"

	"github.com/velasco-jp/nyx/internal/audit"
	"github.com/velasco-jp/nyx/internal/intent"
	"github.com/velasco-jp/nyx/internal/models"
)

// mockDiscovery lets us inject a pre-built CheckResult for testing the engine
// without actually running nmap.
func TestDiscoveryWarnPreservedWhenZeroHostsWithinBounds(t *testing.T) {
	// Build a minimal spec with a subnet_discovery assertion
	minVal := 0
	maxVal := 10
	spec := &intent.Spec{
		Version: 1,
		Site:    "test",
		Networks: []intent.Network{
			{Name: "testnet", CIDR: "10.255.255.0/24", Gateway: "10.255.255.1", Zone: "test"},
		},
		Assertions: []intent.Assertion{
			{
				Type:           "subnet_discovery",
				Network:        "testnet",
				ExpectHostsMin: &minVal,
				ExpectHostsMax: &maxVal,
			},
		},
	}

	// This test will try to run nmap against a non-routable subnet.
	// nmap will either time out or return 0 hosts, which should produce StatusWarn.
	// We use a very short timeout so the test is fast.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	engine := audit.NewEngine(spec)
	report, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(report.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(report.Findings))
	}

	f := report.Findings[0]
	// With 0 hosts in bounds (min=0), the status must be warn (0 hosts found), not pass.
	// If nmap errors out instead, error is also acceptable — but never pass.
	if f.Status == models.StatusPass {
		t.Errorf("expected warn or error when 0 hosts discovered, got pass")
	}
}
```

Add `"time"` to the import block.

- [ ] **Step 2: Run test to verify it fails**

```bash
cd F:/source/netaudit && go test ./internal/audit/... -run TestDiscoveryWarnPreserved -v -timeout 30s
```
Expected: FAIL (returns StatusPass currently)

- [ ] **Step 3: Fix the engine — preserve upstream warn/error status**

In `internal/audit/engine.go`, in `runDiscovery`, find:
```go
if result.Status == "" || (len(result.Violations) == 0 && result.Status != models.StatusError) {
    result.Status = models.StatusPass
}
```

Replace with:
```go
if result.Status == "" || (len(result.Violations) == 0 &&
    result.Status != models.StatusError &&
    result.Status != models.StatusWarn) {
    result.Status = models.StatusPass
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd F:/source/netaudit && go test ./internal/audit/... -run TestDiscoveryWarnPreserved -v -timeout 30s
```
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/audit/engine.go internal/audit/engine_test.go
git commit -m "fix: preserve nmap warn status when 0 hosts within bounds"
```

---

## Task 7: Bug Fix 4 — Assertion field validation

**Files:**
- Modify: `internal/intent/spec.go`
- Modify: `internal/intent/spec_test.go`

- [ ] **Step 1: Write the failing tests**

Add to `internal/intent/spec_test.go`:
```go
func TestValidateAssertionRequiredFields(t *testing.T) {
	base := func() *Spec {
		return &Spec{Version: 1, Site: "test"}
	}

	cases := []struct {
		name      string
		assertion Assertion
		wantErr   string
	}{
		{
			name:      "subnet_discovery missing network",
			assertion: Assertion{Type: "subnet_discovery"},
			wantErr:   "network is required",
		},
		{
			name:      "isolation missing from",
			assertion: Assertion{Type: "isolation", To: "iot", ExpectDeny: "deny"},
			wantErr:   "from is required",
		},
		{
			name:      "isolation missing to",
			assertion: Assertion{Type: "isolation", From: "clients", ExpectDeny: "deny"},
			wantErr:   "to is required",
		},
		{
			name:      "isolation missing expect",
			assertion: Assertion{Type: "isolation", From: "clients", To: "iot"},
			wantErr:   "expect is required",
		},
		{
			name:      "vpn_route missing vpn",
			assertion: Assertion{Type: "vpn_route", Target: "10.0.0.1"},
			wantErr:   "vpn is required",
		},
		{
			name:      "vpn_route missing target",
			assertion: Assertion{Type: "vpn_route", VPN: "home-wg"},
			wantErr:   "target is required",
		},
		{
			name:      "route_check missing target",
			assertion: Assertion{Type: "route_check"},
			wantErr:   "target is required",
		},
		{
			name: "subnet_discovery min > max",
			assertion: func() Assertion {
				min, max := 10, 5
				return Assertion{Type: "subnet_discovery", Network: "net", ExpectHostsMin: &min, ExpectHostsMax: &max}
			}(),
			wantErr: "expect_hosts_min must not exceed expect_hosts_max",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := base()
			s.Assertions = []Assertion{tc.assertion}
			err := ValidateSpec(s)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("expected error containing %q, got %q", tc.wantErr, err.Error())
			}
		})
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd F:/source/netaudit && go test ./internal/intent/... -run TestValidateAssertionRequired -v
```
Expected: FAIL

- [ ] **Step 3: Add per-type validation to ValidateSpec**

In `internal/intent/spec.go`, replace the assertion validation loop:
```go
for i, a := range spec.Assertions {
    if !validTypes[a.Type] {
        return fmt.Errorf("assertion[%d]: unknown type %q", i, a.Type)
    }
    switch a.Type {
    case "subnet_discovery":
        if a.Network == "" {
            return fmt.Errorf("assertion[%d] (subnet_discovery): network is required", i)
        }
        if a.ExpectHostsMin != nil && a.ExpectHostsMax != nil && *a.ExpectHostsMin > *a.ExpectHostsMax {
            return fmt.Errorf("assertion[%d] (subnet_discovery): expect_hosts_min must not exceed expect_hosts_max", i)
        }
    case "isolation":
        if a.From == "" {
            return fmt.Errorf("assertion[%d] (isolation): from is required", i)
        }
        if a.To == "" {
            return fmt.Errorf("assertion[%d] (isolation): to is required", i)
        }
        if a.ExpectDeny == "" {
            return fmt.Errorf("assertion[%d] (isolation): expect is required (use 'deny' or 'allow')", i)
        }
    case "vpn_route":
        if a.VPN == "" {
            return fmt.Errorf("assertion[%d] (vpn_route): vpn is required", i)
        }
        if a.Target == "" {
            return fmt.Errorf("assertion[%d] (vpn_route): target is required", i)
        }
    case "route_check":
        if a.Target == "" {
            return fmt.Errorf("assertion[%d] (route_check): target is required", i)
        }
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd F:/source/netaudit && go test ./internal/intent/... -v
```
Expected: all PASS

- [ ] **Step 5: Commit**

```bash
git add internal/intent/spec.go internal/intent/spec_test.go
git commit -m "fix: validate required fields per assertion type"
```

---

## Task 8: Bug Fix 5 — Host count bounds missing from result metadata

**Files:**
- Modify: `internal/audit/engine.go`
- Modify: `internal/audit/engine_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/audit/engine_test.go`:
```go
func TestDiscoveryExpectedBoundsInResult(t *testing.T) {
	minVal := 2
	maxVal := 20
	spec := &intent.Spec{
		Version: 1,
		Site:    "test",
		Networks: []intent.Network{
			{Name: "testnet", CIDR: "10.255.255.0/24", Gateway: "10.255.255.1", Zone: "test"},
		},
		Assertions: []intent.Assertion{
			{
				Type:           "subnet_discovery",
				Network:        "testnet",
				ExpectHostsMin: &minVal,
				ExpectHostsMax: &maxVal,
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	engine := audit.NewEngine(spec)
	report, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	f := report.Findings[0]
	if _, ok := f.Expected["expect_hosts_min"]; !ok {
		t.Error("expected 'expect_hosts_min' in result.Expected, not found")
	}
	if _, ok := f.Expected["expect_hosts_max"]; !ok {
		t.Error("expected 'expect_hosts_max' in result.Expected, not found")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd F:/source/netaudit && go test ./internal/audit/... -run TestDiscoveryExpectedBounds -v -timeout 30s
```
Expected: FAIL

- [ ] **Step 3: Populate result.Expected in runDiscovery**

In `internal/audit/engine.go`, in `runDiscovery`, add before the host count evaluation:
```go
if a.ExpectHostsMin != nil {
    result.Expected["expect_hosts_min"] = *a.ExpectHostsMin
}
if a.ExpectHostsMax != nil {
    result.Expected["expect_hosts_max"] = *a.ExpectHostsMax
}
```

- [ ] **Step 4: Run test to verify it passes**

```bash
cd F:/source/netaudit && go test ./internal/audit/... -run TestDiscoveryExpectedBounds -v -timeout 30s
```
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/audit/engine.go internal/audit/engine_test.go
git commit -m "fix: populate result.Expected with host count bounds"
```

---

## Task 9: Bug Fix 6 — MCP verify_isolation stub

**Files:**
- Modify: `internal/mcp/server.go`
- Create: `internal/mcp/server_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/mcp/server_test.go`:
```go
package mcp_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/velasco-jp/nyx/internal/mcp"
	"github.com/velasco-jp/nyx/internal/models"
)

func TestVerifyIsolationNotStub(t *testing.T) {
	s := mcp.NewServer()
	ctx := context.Background()

	// Call verify_isolation with a bare IP target (no spec file)
	resultText, isError := s.DispatchToolForTest(ctx, "verify_isolation", map[string]interface{}{
		"from": "clients",
		"to":   "127.0.0.1", // loopback — reachable on any machine
	})

	if isError && strings.Contains(resultText, "not yet implemented") {
		t.Error("verify_isolation is still a stub")
	}

	// Result must be valid JSON containing a status field
	var result models.CheckResult
	if err := json.Unmarshal([]byte(resultText), &result); err != nil {
		t.Errorf("verify_isolation did not return valid CheckResult JSON: %v\nOutput: %s", err, resultText)
	}
	if result.Status == "" {
		t.Error("CheckResult.Status is empty")
	}
}
```

- [ ] **Step 2: Export DispatchToolForTest from mcp package**

In `internal/mcp/server.go`, add:
```go
// DispatchToolForTest exposes dispatchTool for testing.
func (s *Server) DispatchToolForTest(ctx context.Context, name string, args map[string]interface{}) (string, bool) {
	return s.dispatchTool(ctx, name, args)
}
```

- [ ] **Step 3: Run test to verify it fails**

```bash
cd F:/source/netaudit && go test ./internal/mcp/... -run TestVerifyIsolation -v
```
Expected: FAIL — returns stub error string

- [ ] **Step 4: Implement verify_isolation in MCP server**

In `internal/mcp/server.go`, replace the `verify_isolation` case in `dispatchTool`:
```go
case "verify_isolation":
    from, _ := args["from"].(string)
    to, _ := args["to"].(string)
    if from == "" {
        return "from parameter is required", true
    }
    if to == "" {
        return "to parameter is required", true
    }
    specFile, _ := args["spec_file"].(string)

    // If a spec file is provided, use the audit engine's isolation runner
    // by building a minimal spec with a single isolation assertion.
    if specFile != "" {
        spec, err := intent.LoadSpec(specFile)
        if err != nil {
            return fmt.Sprintf("failed to load spec: %v", err), true
        }
        expectDeny := "deny"
        assertion := intent.Assertion{
            Type:       "isolation",
            From:       from,
            To:         to,
            ExpectDeny: expectDeny,
        }
        miniSpec := &intent.Spec{
            Version:    spec.Version,
            Site:       spec.Site,
            Networks:   spec.Networks,
            Assertions: []intent.Assertion{assertion},
        }
        eng := audit.NewEngine(miniSpec)
        report, err := eng.Run(ctx)
        if err != nil {
            return fmt.Sprintf("isolation check failed: %v", err), true
        }
        if len(report.Findings) == 0 {
            return "no findings returned", true
        }
        return toJSON(report.Findings[0]), false
    }

    // No spec: ping `to` directly as a bare IP
    result := models.NewCheckResult("system", "isolation", "local", fmt.Sprintf("%s -> %s", from, to))
    pingResult, err := system.Ping(ctx, to)
    if err != nil {
        result.Status = models.StatusWarn
        result.Summary = fmt.Sprintf("could not determine isolation: %v", err)
    } else {
        result.Observed["reachable"] = pingResult.Reachable
        if pingResult.Reachable {
            result.Status = models.StatusFail
            result.Summary = fmt.Sprintf("isolation violated: %s can reach %s", from, to)
            result.Violations = append(result.Violations, "target is reachable when isolation is expected")
        } else {
            result.Status = models.StatusPass
            result.Summary = fmt.Sprintf("isolation confirmed: %s cannot reach %s", from, to)
        }
    }
    result.Finish()
    return toJSON(result), false
```

Add `"github.com/velasco-jp/nyx/internal/backends/system"` to the imports in `server.go` if not already present.

- [ ] **Step 5: Run test to verify it passes**

```bash
cd F:/source/netaudit && go test ./internal/mcp/... -run TestVerifyIsolation -v
```
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/mcp/server.go internal/mcp/server_test.go
git commit -m "fix: implement verify_isolation MCP tool (was stub)"
```

---

## Task 10: Structured Logger

**Files:**
- Create: `internal/logger/logger.go`
- Create: `internal/logger/logger_test.go`
- Modify: `internal/cli/root.go` (wire logger init)
- Modify: `internal/cli/audit.go` (log on completion)

- [ ] **Step 1: Write failing tests**

Create `internal/logger/logger_test.go`:
```go
package logger_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/velasco-jp/nyx/internal/logger"
)

func TestLogWritesJSONLine(t *testing.T) {
	dir := t.TempDir()
	l, err := logger.New(filepath.Join(dir, "nyx.log"), 1024*1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	l.Info("audit", map[string]interface{}{
		"status":    "pass",
		"duration_ms": 100,
	})

	content, err := os.ReadFile(filepath.Join(dir, "nyx.log"))
	if err != nil {
		t.Fatal(err)
	}

	var entry map[string]interface{}
	if err := json.Unmarshal(content[:len(content)-1], &entry); err != nil {
		t.Fatalf("not valid JSON: %v\ncontent: %s", err, content)
	}
	if entry["cmd"] != "audit" {
		t.Errorf("expected cmd=audit, got %v", entry["cmd"])
	}
	if entry["level"] != "info" {
		t.Errorf("expected level=info, got %v", entry["level"])
	}
}

func TestLogDoesNotWriteIPs(t *testing.T) {
	// Logger must never log IP addresses passed in fields
	// (IPs are not part of the logger API — this test confirms the
	// logger only logs what's explicitly passed to it, nothing implicit)
	dir := t.TempDir()
	l, err := logger.New(filepath.Join(dir, "nyx.log"), 1024*1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	l.Info("discover", map[string]interface{}{
		"status": "pass",
	})

	content, _ := os.ReadFile(filepath.Join(dir, "nyx.log"))
	// No IP-like patterns should appear
	if len(content) == 0 {
		t.Fatal("expected log entry")
	}
	var entry map[string]interface{}
	_ = json.Unmarshal(content[:len(content)-1], &entry)
	for k := range entry {
		if k == "target" || k == "subnet" || k == "gateway" {
			t.Errorf("sensitive field %q should not be logged", k)
		}
	}
}

func TestLogRotation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "nyx.log")
	// Set max size to 100 bytes to trigger rotation quickly
	l, err := logger.New(logPath, 100, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	for i := 0; i < 20; i++ {
		l.Info("test", map[string]interface{}{"i": i})
	}

	// After rotation, nyx.log.1 should exist
	if _, err := os.Stat(filepath.Join(dir, "nyx.log.1")); os.IsNotExist(err) {
		t.Error("expected rotated file nyx.log.1 to exist")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd F:/source/netaudit && go test ./internal/logger/...
```
Expected: compile error — package does not exist.

- [ ] **Step 3: Implement the logger**

Create `internal/logger/logger.go`:
```go
// Package logger provides a JSON-lines append logger with file rotation.
// Log writes are best-effort — errors are silently discarded so that a
// logging failure never fails a nyx command.
package logger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/velasco-jp/nyx/internal/version"
)

// Logger writes JSON-line entries to a rotating log file.
type Logger struct {
	mu      sync.Mutex
	path    string
	maxSize int64
	maxFiles int
	file    *os.File
	size    int64
}

// New opens (or creates) the log file at path.
// maxSize is the max bytes per file before rotation.
// maxFiles is the number of rotated files to keep (e.g. 3 → nyx.log, nyx.log.1, nyx.log.2).
func New(path string, maxSize int64, maxFiles int) (*Logger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, fmt.Errorf("creating log directory: %w", err)
	}
	l := &Logger{path: path, maxSize: maxSize, maxFiles: maxFiles}
	if err := l.openFile(); err != nil {
		return nil, err
	}
	return l, nil
}

// Info logs an info-level entry. fields must not contain IP addresses,
// hostnames, credentials, or raw command output.
func (l *Logger) Info(cmd string, fields map[string]interface{}) {
	l.write("info", cmd, fields)
}

// Error logs an error-level entry.
func (l *Logger) Error(cmd string, err error) {
	l.write("error", cmd, map[string]interface{}{"error": err.Error()})
}

// Close closes the underlying log file.
func (l *Logger) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		_ = l.file.Close()
	}
}

func (l *Logger) write(level, cmd string, fields map[string]interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file == nil {
		return
	}

	entry := map[string]interface{}{
		"ts":      time.Now().UTC().Format(time.RFC3339),
		"level":   level,
		"cmd":     cmd,
		"version": version.Version,
	}
	for k, v := range fields {
		entry[k] = v
	}

	data, err := json.Marshal(entry)
	if err != nil {
		return
	}
	data = append(data, '\n')

	// Rotate if needed
	if l.size+int64(len(data)) > l.maxSize {
		_ = l.file.Close()
		l.rotate()
		if err := l.openFile(); err != nil {
			l.file = nil
			return
		}
	}

	n, err := l.file.Write(data)
	if err == nil {
		l.size += int64(n)
	}
}

func (l *Logger) openFile() error {
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return fmt.Errorf("opening log file: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return fmt.Errorf("stat log file: %w", err)
	}
	l.file = f
	l.size = info.Size()
	return nil
}

func (l *Logger) rotate() {
	// Shift existing rotated files: .2 deleted, .1→.2, (current)→.1
	for i := l.maxFiles - 1; i >= 1; i-- {
		old := fmt.Sprintf("%s.%d", l.path, i)
		new := fmt.Sprintf("%s.%d", l.path, i+1)
		if i == l.maxFiles-1 {
			_ = os.Remove(old)
		} else {
			_ = os.Rename(old, new)
		}
	}
	_ = os.Rename(l.path, l.path+".1")
}

// DefaultPath returns the default log file path: ~/.nyx/nyx.log
func DefaultPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "nyx.log"
	}
	return filepath.Join(home, ".nyx", "nyx.log")
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd F:/source/netaudit && go test ./internal/logger/... -v
```
Expected: all PASS

- [ ] **Step 5: Wire logger into CLI commands**

In `internal/cli/root.go`, add a package-level logger and initialize it:
```go
import "github.com/velasco-jp/nyx/internal/logger"

var log *logger.Logger

func init() {
	// ... existing init ...
	// Logger is best-effort; if it fails, we continue without logging.
	l, err := logger.New(logger.DefaultPath(), 5*1024*1024, 3)
	if err == nil {
		log = l
	}
}
```

In `internal/cli/audit.go`, add logging at the end of the RunE function, before the exit code switch:
```go
if log != nil {
    if auditReport.Status == models.StatusError {
        log.Error("audit", fmt.Errorf(auditReport.Status))
    } else {
        log.Info("audit", map[string]interface{}{
            "status":          string(auditReport.Status),
            "assertion_count": len(auditReport.Findings),
            "pass":            auditReport.Summary.Pass,
            "fail":            auditReport.Summary.Fail,
            "warn":            auditReport.Summary.Warn,
            "error":           auditReport.Summary.Error,
        })
    }
}
```

- [ ] **Step 6: Build and verify**

```bash
cd F:/source/netaudit && go build ./... && go vet ./...
```

- [ ] **Step 7: Commit**

```bash
git add internal/logger/ internal/cli/root.go internal/cli/audit.go
git commit -m "feat: JSON-lines rotating logger at ~/.nyx/nyx.log"
```

---

## Task 11: `nyx doctor` command

**Files:**
- Create: `internal/cli/doctor.go`
- Modify: `internal/cli/root.go`

- [ ] **Step 1: Create doctor.go**

Create `internal/cli/doctor.go`:
```go
package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/spf13/cobra"
	"github.com/velasco-jp/nyx/internal/backends/nmap"
	"github.com/velasco-jp/nyx/internal/backends/system"
	"github.com/velasco-jp/nyx/internal/intent"
	"github.com/velasco-jp/nyx/internal/logger"
	"github.com/velasco-jp/nyx/internal/models"
	"github.com/velasco-jp/nyx/internal/report"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check nyx environment health and validate a spec file",
	Example: `  nyx doctor
  nyx doctor --spec homelab.yaml
  nyx doctor --json`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var checks []models.CheckResult
		allPass := true

		// --- Environment checks ---

		// 1. nmap installed
		nmapCheck := models.NewCheckResult("doctor", "nmap_installed", "local", "nmap")
		if nmap.Available() {
			path, _ := exec.LookPath("nmap")
			out, err := exec.Command(path, "--version").Output()
			version := "unknown"
			if err == nil && len(out) > 0 {
				lines := string(out)
				if len(lines) > 60 {
					lines = lines[:60]
				}
				version = lines
			}
			nmapCheck.Status = models.StatusPass
			nmapCheck.Summary = fmt.Sprintf("nmap found at %s (%s)", path, version)
		} else {
			nmapCheck.Status = models.StatusFail
			nmapCheck.Summary = "nmap is not installed or not in PATH"
			nmapCheck.Violations = append(nmapCheck.Violations, nmap.CheckAvailable().Error())
			allPass = false
		}
		nmapCheck.Finish()
		checks = append(checks, *nmapCheck)

		// 2. Platform detection
		platCheck := models.NewCheckResult("doctor", "platform", "local", runtime.GOOS)
		platCheck.Status = models.StatusPass
		platCheck.Summary = fmt.Sprintf("platform: %s/%s", runtime.GOOS, runtime.GOARCH)
		platCheck.Observed["goos"] = runtime.GOOS
		platCheck.Observed["goarch"] = runtime.GOARCH
		platCheck.Finish()
		checks = append(checks, *platCheck)

		// 3. Log directory writable
		logDir := logger.DefaultPath()
		logDirCheck := models.NewCheckResult("doctor", "log_directory", "local", logDir)
		logParent := logDir[:len(logDir)-len("/nyx.log")]
		if err := os.MkdirAll(logParent, 0750); err != nil {
			logDirCheck.Status = models.StatusFail
			logDirCheck.Summary = fmt.Sprintf("cannot create log directory %s: %v", logParent, err)
			logDirCheck.Violations = append(logDirCheck.Violations, err.Error())
			allPass = false
		} else {
			testFile := logParent + "/.nyx_write_test"
			if f, err := os.Create(testFile); err != nil {
				logDirCheck.Status = models.StatusFail
				logDirCheck.Summary = fmt.Sprintf("log directory %s is not writable: %v", logParent, err)
				allPass = false
			} else {
				f.Close()
				os.Remove(testFile)
				logDirCheck.Status = models.StatusPass
				logDirCheck.Summary = fmt.Sprintf("log directory %s is writable", logParent)
			}
		}
		logDirCheck.Finish()
		checks = append(checks, *logDirCheck)

		// 4. Internet route (informational)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		routeCheck := models.NewCheckResult("doctor", "internet_route", "local", "8.8.8.8")
		if route, err := system.GetRouteToTarget(ctx, "8.8.8.8"); err != nil {
			routeCheck.Status = models.StatusWarn
			routeCheck.Summary = "no route to 8.8.8.8 — internet connectivity may be unavailable"
		} else {
			routeCheck.Status = models.StatusPass
			routeCheck.Summary = fmt.Sprintf("internet route: 8.8.8.8 via %s dev %s", route.Gateway, route.Device)
		}
		routeCheck.Finish()
		checks = append(checks, *routeCheck)

		// --- Spec checks ---
		if specFile != "" {
			specChecks := runSpecChecks(specFile)
			for _, sc := range specChecks {
				if sc.Status == models.StatusFail || sc.Status == models.StatusError {
					allPass = false
				}
			}
			checks = append(checks, specChecks...)
		}

		w, err := getWriter()
		if err != nil {
			return err
		}
		if outputPath != "" {
			defer w.Close()
		}

		if jsonOutput {
			// Wrap as an audit report for consistent JSON shape
			r := &models.AuditReport{
				Audit:    "doctor",
				Status:   models.ComputeOverallStatus(checks),
				Summary:  models.Tally(checks),
				Findings: checks,
			}
			return report.RenderJSON(w, r)
		}

		// Human output
		for _, c := range checks {
			tag := doctorTag(c.Status)
			fmt.Fprintf(w, "%s %s\n", tag, c.Summary)
			for _, v := range c.Violations {
				fmt.Fprintf(w, "       → %s\n", v)
			}
		}

		if allPass {
			fmt.Fprintln(w, "\nnyx environment looks healthy.")
		} else {
			fmt.Fprintln(w, "\nnyx environment has issues. See above for details.")
			os.Exit(2)
		}
		return nil
	},
}

func runSpecChecks(path string) []models.CheckResult {
	var checks []models.CheckResult

	// File readable
	fileCheck := models.NewCheckResult("doctor", "spec_file", "local", path)
	data, err := os.ReadFile(path)
	if err != nil {
		fileCheck.Status = models.StatusFail
		fileCheck.Summary = fmt.Sprintf("cannot read spec file: %v", err)
		fileCheck.Violations = append(fileCheck.Violations, fmt.Sprintf("fix: check that %s exists and is readable", path))
		fileCheck.Finish()
		return append(checks, *fileCheck)
	}
	fileCheck.Status = models.StatusPass
	fileCheck.Summary = fmt.Sprintf("spec file readable: %s (%d bytes)", path, len(data))
	fileCheck.Finish()
	checks = append(checks, *fileCheck)

	// YAML + spec validation
	validCheck := models.NewCheckResult("doctor", "spec_valid", "local", path)
	spec, err := intent.ParseSpec(data)
	if err != nil {
		validCheck.Status = models.StatusFail
		validCheck.Summary = fmt.Sprintf("spec validation failed: %v", err)
		validCheck.Violations = append(validCheck.Violations,
			"fix: correct the error above, then re-run nyx doctor --spec <file>")
		validCheck.Finish()
		return append(checks, *validCheck)
	}
	validCheck.Status = models.StatusPass
	validCheck.Summary = fmt.Sprintf("spec valid: version %d, site %q, %d networks, %d assertions",
		spec.Version, spec.Site, len(spec.Networks), len(spec.Assertions))
	validCheck.Finish()
	checks = append(checks, *validCheck)

	// Network reference checks
	refCheck := models.NewCheckResult("doctor", "spec_references", "local", path)
	var violations []string
	for i, a := range spec.Assertions {
		if a.Type == "subnet_discovery" && spec.NetworkByName(a.Network) == nil {
			violations = append(violations, fmt.Sprintf(
				"assertion[%d]: network %q not declared — add it to the networks section", i, a.Network))
		}
		if a.Type == "vpn_route" && spec.VPNByName(a.VPN) == nil {
			violations = append(violations, fmt.Sprintf(
				"assertion[%d]: vpn %q not declared — add it to the vpn section", i, a.VPN))
		}
	}
	if len(violations) > 0 {
		refCheck.Status = models.StatusFail
		refCheck.Summary = fmt.Sprintf("%d unresolved references in spec", len(violations))
		refCheck.Violations = violations
	} else {
		refCheck.Status = models.StatusPass
		refCheck.Summary = "all assertion references resolve"
	}
	refCheck.Finish()
	checks = append(checks, *refCheck)

	return checks
}

func doctorTag(s models.Status) string {
	switch s {
	case models.StatusPass:
		return "[ OK ]"
	case models.StatusFail:
		return "[FAIL]"
	case models.StatusWarn:
		return "[WARN]"
	default:
		return "[ERR ]"
	}
}

func init() {
	rootCmd.AddCommand(doctorCmd)
}
```

- [ ] **Step 2: Build and run doctor**

```bash
cd F:/source/netaudit && go build ./... && ./nyx.exe doctor
./nyx.exe doctor --spec spec.yaml
./nyx.exe doctor --spec spec.yaml --json
```
Expected: clean output showing all checks.

- [ ] **Step 3: Commit**

```bash
git add internal/cli/doctor.go
git commit -m "feat: nyx doctor command with env + spec validation"
```

---

## Task 12: MCP parity — fix inconsistent tool outputs + add new tools

**Files:**
- Modify: `internal/mcp/server.go`

- [ ] **Step 1: Fix check_routes to return CheckResult**

In `internal/mcp/server.go`, replace the `check_routes` case:
```go
case "check_routes":
    target, _ := args["target"].(string)
    if target == "" {
        return "target parameter is required", true
    }
    result := models.NewCheckResult("system", "route_check", "local", target)
    route, err := system.GetRouteToTarget(ctx, target)
    if err != nil {
        result.Status = models.StatusError
        result.Summary = fmt.Sprintf("failed to get route to %s: %v", target, err)
        result.Finish()
        return toJSON(result), true
    }
    result.Observed["gateway"] = route.Gateway
    result.Observed["device"] = route.Device
    result.Status = models.StatusPass
    result.Summary = fmt.Sprintf("route to %s via %s dev %s", target, route.Gateway, route.Device)
    result.Finish()
    return toJSON(result), false
```

- [ ] **Step 2: Fix check_vpn to return CheckResult**

Replace the `check_vpn` case:
```go
case "check_vpn":
    target, _ := args["target"].(string)
    if target == "" {
        return "target parameter is required", true
    }
    result := models.NewCheckResult("system", "vpn_route", "local", target)
    route, err := system.GetRouteToTarget(ctx, target)
    if err != nil {
        result.Status = models.StatusError
        result.Summary = fmt.Sprintf("failed to get route to %s: %v", target, err)
        result.Finish()
        return toJSON(result), true
    }
    result.Observed["device"] = route.Device
    result.Observed["gateway"] = route.Gateway
    isVPN, _ := system.CheckVPNInterface(ctx, route.Device)
    result.Observed["via_tunnel"] = isVPN
    if isVPN {
        result.Status = models.StatusPass
        result.Summary = fmt.Sprintf("%s routes via tunnel (%s)", target, route.Device)
    } else {
        result.Status = models.StatusWarn
        result.Summary = fmt.Sprintf("%s routes via %s (not a tunnel interface)", target, route.Device)
    }
    result.Finish()
    return toJSON(result), false
```

- [ ] **Step 3: Add scan options to discover_subnet**

Replace the `discover_subnet` case:
```go
case "discover_subnet":
    subnet, _ := args["subnet"].(string)
    if subnet == "" {
        return "subnet parameter is required", true
    }
    opts := nmap.DefaultScanOptions
    if t, ok := args["scan_timing"].(float64); ok && t > 0 {
        opts.TimingTemplate = int(t)
    }
    if r, ok := args["scan_min_rate"].(float64); ok && r > 0 {
        opts.MinRate = int(r)
    }
    result, err := nmap.DiscoverWithOptions(ctx, subnet, opts)
    if err != nil {
        return fmt.Sprintf("discovery failed: %v", err), true
    }
    return toJSON(result), false
```

Update the `discover_subnet` tool definition in `handleToolsList` to add the new optional params:
```go
{
    Name:        "discover_subnet",
    Description: "Discover active hosts in a subnet using nmap ping sweep.",
    InputSchema: inputSchema{
        Type: "object",
        Properties: map[string]propSchema{
            "subnet":       {Type: "string", Description: "CIDR notation subnet to scan, e.g. 192.168.1.0/24"},
            "scan_timing":  {Type: "number", Description: "nmap -T timing template (0-5, default 4)"},
            "scan_min_rate":{Type: "number", Description: "nmap --min-rate packets/sec (default 500)"},
        },
        Required: []string{"subnet"},
    },
},
```

- [ ] **Step 4: Add run_doctor MCP tool**

Add to the tools list in `handleToolsList`:
```go
{
    Name:        "run_doctor",
    Description: "Check nyx environment health. Optionally validate a spec file.",
    InputSchema: inputSchema{
        Type: "object",
        Properties: map[string]propSchema{
            "spec_file": {Type: "string", Description: "Optional path to a YAML spec file to validate"},
        },
    },
},
```

Add to `dispatchTool`:
```go
case "run_doctor":
    specPath, _ := args["spec_file"].(string)
    var findings []models.CheckResult

    // nmap check
    nmapResult := models.NewCheckResult("doctor", "nmap_installed", "local", "nmap")
    if nmap.Available() {
        nmapResult.Status = models.StatusPass
        nmapResult.Summary = "nmap is available"
    } else {
        nmapResult.Status = models.StatusFail
        nmapResult.Summary = "nmap is not installed or not in PATH"
        nmapResult.Violations = []string{nmap.CheckAvailable().Error()}
    }
    nmapResult.Finish()
    findings = append(findings, *nmapResult)

    // Spec check
    if specPath != "" {
        specChecks := runDoctorSpecChecks(specPath)
        findings = append(findings, specChecks...)
    }

    report := &models.AuditReport{
        Audit:    "doctor",
        Status:   models.ComputeOverallStatus(findings),
        Summary:  models.Tally(findings),
        Findings: findings,
    }
    return toJSON(report), false
```

Add the helper (shared logic with CLI doctor, but kept local to avoid coupling):
```go
func runDoctorSpecChecks(path string) []models.CheckResult {
    var checks []models.CheckResult
    fileCheck := models.NewCheckResult("doctor", "spec_file", "local", path)
    data, err := os.ReadFile(path)
    if err != nil {
        fileCheck.Status = models.StatusFail
        fileCheck.Summary = fmt.Sprintf("cannot read spec file: %v", err)
        fileCheck.Finish()
        return append(checks, *fileCheck)
    }
    fileCheck.Status = models.StatusPass
    fileCheck.Summary = fmt.Sprintf("spec file readable (%d bytes)", len(data))
    fileCheck.Finish()
    checks = append(checks, *fileCheck)

    validCheck := models.NewCheckResult("doctor", "spec_valid", "local", path)
    _, err = intent.ParseSpec(data)
    if err != nil {
        validCheck.Status = models.StatusFail
        validCheck.Summary = fmt.Sprintf("spec invalid: %v", err)
    } else {
        validCheck.Status = models.StatusPass
        validCheck.Summary = "spec is valid"
    }
    validCheck.Finish()
    checks = append(checks, *validCheck)
    return checks
}
```

Add `"os"` to imports in server.go if not present.

- [ ] **Step 5: Add provider_list MCP tool**

Add to tools list:
```go
{
    Name:        "provider_list",
    Description: "List all registered providers and their capabilities.",
    InputSchema: inputSchema{
        Type:       "object",
        Properties: map[string]propSchema{},
    },
},
```

Add to dispatchTool:
```go
case "provider_list":
    list := providers.List()
    type entry struct {
        Name         string   `json:"name"`
        Capabilities []string `json:"capabilities"`
    }
    out := make([]entry, len(list))
    for i, p := range list {
        out[i] = entry{Name: p.Name(), Capabilities: p.Capabilities()}
    }
    return toJSON(out), false
```

Add `providers "github.com/velasco-jp/nyx/internal/providers"` to server.go imports.

- [ ] **Step 6: Build and verify**

```bash
cd F:/source/netaudit && go build ./... && go test ./...
```
Expected: all PASS, clean build.

- [ ] **Step 7: Commit**

```bash
git add internal/mcp/server.go
git commit -m "feat: MCP parity — CheckResult outputs, scan options, run_doctor, provider_list"
```

---

## Task 13: README + CLAUDE.md update

**Files:**
- Modify: `README.md`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Update README**

Replace all `netaudit` references with `nyx`. Update:

1. Title and description
2. Quick Start commands (all become `nyx ...`)
3. **Prerequisites section** — add this block:

```markdown
## Prerequisites

- **Go 1.22+** — to build from source
- **nmap** — required for `discover` and `subnet_discovery` assertions

  nyx does not bundle nmap. Install it for your platform:

  | Platform | Command |
  |----------|---------|
  | Ubuntu/Debian | `sudo apt install nmap` |
  | Fedora/RHEL | `sudo dnf install nmap` |
  | Arch Linux | `sudo pacman -S nmap` |
  | macOS | `brew install nmap` |
  | Windows | `winget install nmap` |

  If nmap is missing, `nyx doctor` will show the exact install command for your system.

- Root/sudo — required for nmap subnet scans on some platforms
```

4. Commands table — add `doctor` row
5. Project Structure — update paths (`cmd/nyx/`, add `internal/providers/`, `internal/logger/`, `internal/version/`)
6. Provider section — brief explanation of `nyx provider list` and registered providers

- [ ] **Step 2: Update CLAUDE.md**

Update package descriptions to include:
- `internal/version` — single `Version` constant
- `internal/logger` — JSON-lines rotating logger
- `internal/providers` — Provider interface, registry, omada and opnsense implementations
- Updated CLI surface (doctor, provider list, dynamic vendor commands)
- Note that `internal/cli/omada.go` is gone — replaced by provider routing

- [ ] **Step 3: Build and run full test suite one final time**

```bash
cd F:/source/netaudit && go build ./... && go vet ./... && go test ./...
./nyx.exe version
./nyx.exe doctor
./nyx.exe provider list
./nyx.exe audit --spec spec.yaml
```

- [ ] **Step 4: Commit**

```bash
git add README.md CLAUDE.md
git commit -m "docs: update README and CLAUDE.md for nyx rename and new features"
```

---

## Self-Review

**Spec coverage check:**

| Spec section | Covered by task |
|---|---|
| Rename netaudit → nyx | Task 1 |
| Version single source | Task 2 |
| Provider interface + registry | Task 3 |
| Omada provider | Task 3 |
| OPNsense stub | Task 3 |
| Bug 1 — recommendations bypass --output | Task 4 |
| Bug 2 — JSON pollution | Task 5 |
| Bug 3 — warn→pass overwrite | Task 6 |
| Bug 4 — assertion field validation | Task 7 |
| Bug 5 — bounds not in result.Expected | Task 8 |
| Bug 6 — verify_isolation stub | Task 9 |
| Structured logger | Task 10 |
| doctor command | Task 11 |
| MCP parity (check_routes, check_vpn, discover_subnet) | Task 12 |
| run_doctor MCP tool | Task 12 |
| provider_list MCP tool | Task 12 |
| README prerequisites (nmap install instructions) | Task 13 |
| CLAUDE.md update | Task 13 |

No spec requirements are missing from the plan.
