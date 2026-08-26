// Package providers defines the interface for vendor-specific network providers (e.g. omada, opnsense) and the registry.
package providers

import (
	"context"

	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/logger"
	"github.com/jpvelasco/nyx/internal/models"
)

// ImportOptions holds credentials and options for provider connections.
// ClientID/ClientSecret carry the vendor's credential pair: for Omada the
// Open API client credentials, for OPNsense the API key/secret.
type ImportOptions struct {
	Host          string
	ClientID      string
	ClientSecret  string
	Site          string
	Debug         bool
	SkipTLSVerify bool
	CACertPath    string
	// Logger receives structured operation events (token mint, retries,
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
// rule exists from every source in From to every destination in To with the
// given action, on the given scope. Matching against existing rules is
// cover-based: a request is satisfied when the same-action, status-on rule
// of the same scope already covers all requested endpoints with the same
// protocol set.
type ACLApplyRequest struct {
	PolicyName string   // rule name; a default is derived when empty
	From       []string // source network names
	To         []string // destination network names
	Action     string   // "allow" or "deny"
	Scope      string   // "switch" (default) or "gateway"; "eap" is not supported
	Protocols  []int    // IP protocols; empty means all
	DryRun     bool     // preview the change without mutating
}

// ACLApplyResult is the structured outcome of an apply attempt, with
// before/after evidence for auditing. Before and After hold the JSON arrays
// of ACL rules as seen by the controller; they are identical when nothing
// was mutated.
type ACLApplyResult struct {
	DryRun       bool     `json:"dry_run"`
	Outcome      string   `json:"outcome"` // "created" | "enabled" | "unchanged"
	RuleID       string   `json:"rule_id,omitempty"`
	RuleName     string   `json:"rule_name,omitempty"`
	Scope        string   `json:"scope"`      // "switch" or "gateway"
	FromCIDRs    []string `json:"from_cidrs"` // resolved network CIDRs for re-audit
	ToCIDRs      []string `json:"to_cidrs"`
	FromGateways []string `json:"from_gateways,omitempty"` // gateway IPs for re-audit
	ToGateways   []string `json:"to_gateways,omitempty"`
	Before       string   `json:"before"`
	After        string   `json:"after"`
}

// ProviderInventory is the provider's point-in-time observation of a site:
// the device inventory, LAN networks with their gateway bindings, both ACL
// scopes and their rule counts, and the active client count. Human is a
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

// NatCheckRequest is the expected NAT posture for a nat_check assertion:
// an outbound mode (automatic, hybrid, advanced, disabled), a topology role
// (nat_router, bridge, indeterminate), "unknown", or "present" (Omada
// managed-gateway presence).
type NatCheckRequest struct {
	ExpectMode string
}

// NatChecker is the optional read-only surface behind the nat_check
// assertion. The audit engine looks it up with a type assertion (like
// ACLApplier); a provider without it is refused with a clear error.
type NatChecker interface {
	NatCheck(ctx context.Context, req NatCheckRequest, opts ImportOptions) (*models.CheckResult, error)
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
