// Package providers defines the interface for vendor-specific network providers (e.g. omada, opnsense) and the registry.
package providers

import (
	"context"

	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/logger"
	"github.com/jpvelasco/nyx/internal/models"
)

// ImportOptions holds credentials and options for provider connections.
type ImportOptions struct {
	Host          string
	Username      string
	Password      string
	Site          string
	Debug         bool
	SkipTLSVerify bool
	CACertPath    string
	// Logger receives structured operation events (login, retries, session
	// refresh) from provider clients. Never contains credentials.
	Logger *logger.Logger
}

// ProviderInfo holds version and connection metadata returned by Info.
type ProviderInfo struct {
	Provider string            `json:"provider"`
	Host     string            `json:"host"`
	Version  string            `json:"version"`
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

// ACLCheckRequest holds the policy details needed for ACL enforcement checking.
type ACLCheckRequest struct {
	PolicyName     string
	From           string
	To             string
	Action         string // "allow" or "deny"
	ExpectEnforced bool
}

// ACLApplyRequest describes a single desired ACL policy change: ensure a
// rule exists from From to To with the given action.
type ACLApplyRequest struct {
	PolicyName string // rule name; a default is derived when empty
	From       string // source network name
	To         string // destination network name
	Action     string // "allow" or "deny"
	DryRun     bool   // preview the change without mutating
}

// ACLApplyResult is the structured outcome of an apply attempt, with
// before/after evidence for auditing. Before and After hold the JSON arrays
// of ACL rules as seen by the controller; they are identical when nothing
// was mutated.
type ACLApplyResult struct {
	DryRun      bool   `json:"dry_run"`
	Outcome     string `json:"outcome"` // "created" | "enabled" | "unchanged"
	RuleID      string `json:"rule_id,omitempty"`
	FromCIDR    string `json:"from_cidr"` // resolved network CIDRs for re-audit
	ToCIDR      string `json:"to_cidr"`
	FromGateway string `json:"from_gateway,omitempty"` // gateway IPs for re-audit
	ToGateway   string `json:"to_gateway,omitempty"`
	Before      string `json:"before"`
	After       string `json:"after"`
}

// ProviderInventory is the provider's point-in-time observation of a site:
// the device inventory, LAN networks with their gateway bindings, both ACL
// scopes and their enabled state, and the active client count. Human is a
// stable, human-readable rendering.
type ProviderInventory struct {
	Site        string            `json:"site"`
	Human       string            `json:"human"`
	Inventory   *intent.Inventory `json:"inventory"`
	ClientCount int               `json:"client_count"`
	Warnings    []string          `json:"warnings,omitempty"`
}

// InventoryProvider is the optional observation surface behind
// `nyx <vendor> inventory` and the MCP inventory tool.
type InventoryProvider interface {
	Inventory(ctx context.Context, opts ImportOptions) (*ProviderInventory, error)
}

// ACLApplier is the optional mutation surface a provider may implement.
// Providers that cannot mutate return ErrCapabilityUnsupported behaviour
// through the service layer when ApplyACL is requested.
type ACLApplier interface {
	ApplyACL(ctx context.Context, req ACLApplyRequest, opts ImportOptions) (*ACLApplyResult, error)
}

// Provider is implemented by each vendor backend.
type Provider interface {
	Name() string
	Capabilities() []string
	Info(ctx context.Context, opts ImportOptions) (*ProviderInfo, error)
	ImportSpec(ctx context.Context, opts ImportOptions) (*ImportResult, error)
	Check(ctx context.Context, opts ImportOptions) (*AuditResult, error)
	CheckACL(ctx context.Context, req ACLCheckRequest, opts ImportOptions) (*models.CheckResult, error)
}

// ErrCapabilityUnsupported is returned when a provider does not support an operation.
type ErrCapabilityUnsupported struct {
	Provider   string
	Capability string
}

func (e *ErrCapabilityUnsupported) Error() string {
	return "provider \"" + e.Provider + "\" does not support \"" + e.Capability + "\""
}
