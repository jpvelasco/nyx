package service

import (
	"context"
	"errors"
	"slices"

	"github.com/jpvelasco/nyx/internal/providers"
)

// InfoOperation declares both transport names and the one typed read they call.
type InfoOperation struct {
	providers.InfoReader
	Provider      string
	CLIName       string
	MCPName       string
	Authenticated bool
}

// ControllerInfo returns the read an adapter advertises, without connecting to the device.
func ControllerInfo(p providers.Adapter) (InfoOperation, bool) {
	reader, ok := p.(providers.InfoReader)
	if !ok || !slices.Contains(p.Capabilities(), "info") {
		return InfoOperation{}, false
	}
	authenticated := true
	if public, ok := p.(interface{ PublicInfo() bool }); ok {
		authenticated = !public.PublicInfo()
	}
	return InfoOperation{InfoReader: reader, Provider: p.Name(), CLIName: "info", MCPName: p.Name() + "_get_info", Authenticated: authenticated}, true
}

// Read performs the declared operation and redacts credentials from adapter errors.
func (op InfoOperation) Read(ctx context.Context, opts providers.ImportOptions) (*providers.ProviderInfo, error) {
	info, err := op.Info(ctx, opts)
	if err != nil {
		return nil, opts.Connection.RedactError(err, opts.Credentials)
	}
	if info == nil {
		return nil, errors.New("controller returned no information")
	}
	return info, nil
}

// AgentInfo projects the historical vendor tool shapes. New adapters use ProviderInfo.
func (op InfoOperation) AgentInfo(info *providers.ProviderInfo) any {
	switch op.Provider {
	case "omada":
		return OmadaInfo{Provider: info.Provider, Host: info.Host, Version: info.Version, APIVersion: info.Extra["api_version"], OmadaCID: info.Extra["omada_cid"], Configured: info.Configured}
	case "opnsense":
		return OpnsenseInfo{Provider: info.Provider, Host: info.Host, Version: info.Version, Product: info.Extra["product"], Arch: info.Extra["arch"]}
	default:
		return info
	}
}
