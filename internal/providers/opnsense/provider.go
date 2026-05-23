package opnsense

import (
	"context"
	"fmt"

	providers "github.com/velasco-jp/nyx/internal/providers"
)

// OPNsenseProvider implements providers.Provider for OPNsense firewalls.
// Currently only Info is implemented. ImportSpec and Check return ErrCapabilityUnsupported.
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

var _ providers.Provider = (*OPNsenseProvider)(nil)

func init() {
	providers.Register(&OPNsenseProvider{})
}
