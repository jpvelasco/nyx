// Package providers defines the interface for vendor-specific network providers (e.g. omada, opnsense) and the registry.
package providers

import (
	"context"

	"github.com/jpvelasco/nyx/internal/intent"
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

// Provider is implemented by each vendor backend.
type Provider interface {
	Name() string
	Capabilities() []string
	Info(ctx context.Context, opts ImportOptions) (*ProviderInfo, error)
	ImportSpec(ctx context.Context, opts ImportOptions) (*ImportResult, error)
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
