package service

import (
	"context"

	opnsensebackend "github.com/jpvelasco/nyx/internal/providers/opnsense"
)

// OpnsenseOptions carries everything needed to talk to an OPNsense firewall
// via its REST API. The API secret is held only for the duration of a
// request; it is never written to logs, evidence, or tool output.
type OpnsenseOptions struct {
	Host          string
	APIKey        string
	APISecret     string
	SkipTLSVerify bool
	CACertPath    string
}

// OpnsenseInfo is the system metadata surfaced to agents.
type OpnsenseInfo struct {
	Provider string `json:"provider"`
	Host     string `json:"host"`
	Version  string `json:"version"`
	Product  string `json:"product"`
	Arch     string `json:"arch"`
}

// OpnsenseService exposes the OPNsense observation surface shared by the MCP
// server and any future CLI commands. NewClient is a seam for tests.
type OpnsenseService struct {
	NewClient func(host, apiKey, apiSecret string, skipTLSVerify bool, caCertPath string) *opnsensebackend.Client
}

// NewOpnsenseService creates an OpnsenseService using the real client.
func NewOpnsenseService() *OpnsenseService {
	return &OpnsenseService{NewClient: opnsensebackend.NewClient}
}

// Info fetches system metadata from the firewall (version, product, arch).
func (s *OpnsenseService) Info(ctx context.Context, opts OpnsenseOptions) (*OpnsenseInfo, error) {
	client := s.client(opts)
	sys, err := client.GetSystemInformation(ctx)
	if err != nil {
		return nil, err
	}
	return &OpnsenseInfo{
		Provider: "opnsense",
		Host:     opts.Host,
		Version:  sys.ProductVersion(),
		Product:  "OPNsense",
		Arch:     sys.Arch(),
	}, nil
}

func (s *OpnsenseService) client(opts OpnsenseOptions) *opnsensebackend.Client {
	return s.NewClient(opts.Host, opts.APIKey, opts.APISecret, opts.SkipTLSVerify, opts.CACertPath)
}
