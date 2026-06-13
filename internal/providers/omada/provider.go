// Package omadaprovider implements the providers.Provider interface for TP-Link Omada SDN controllers (v6+).
package omadaprovider

import (
	"context"
	"fmt"

	"github.com/jpvelasco/nyx/internal/audit"
	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
	providers "github.com/jpvelasco/nyx/internal/providers"
)

// OmadaProvider implements providers.Provider for TP-Link Omada SDN controllers.
type OmadaProvider struct{}

// Name returns the provider identifier "omada".
func (o *OmadaProvider) Name() string { return "omada" }

// Capabilities lists the supported operations for this provider.
func (o *OmadaProvider) Capabilities() []string {
	return []string{"info", "import", "check"}
}

// Info returns basic controller information without requiring authentication.
func (o *OmadaProvider) Info(ctx context.Context, opts providers.ImportOptions) (*providers.ProviderInfo, error) {
	client, err := omadabackend.NewClient(ctx, opts.Host, opts.SkipTLSVerify, opts.CACertPath)
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

// ImportSpec imports networks, policies, and clients from the Omada controller and returns a generated intent spec.
func (o *OmadaProvider) ImportSpec(ctx context.Context, opts providers.ImportOptions) (*providers.ImportResult, error) {
	result, err := omadabackend.ImportSpec(ctx, opts.Host, opts.Username, opts.Password, opts.Site, opts.Debug, opts.SkipTLSVerify, opts.CACertPath)
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

// Check imports a spec from the controller and runs an audit against it.
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

var _ providers.Provider = (*OmadaProvider)(nil)

func init() {
	providers.Register(&OmadaProvider{})
}
