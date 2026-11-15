package service

import (
	"context"
)

// OpnsenseWireGuardServer is one observed WireGuard server instance.
type OpnsenseWireGuardServer struct {
	UUID          string   `json:"uuid"`
	Name          string   `json:"name,omitempty"`
	Enabled       bool     `json:"enabled"`
	TunnelAddress string   `json:"tunnel_address,omitempty"`
	ListenPort    int      `json:"listen_port,omitempty"`
	Peers         []string `json:"peers,omitempty"`
}

// OpnsenseWireGuardClient is one observed WireGuard peer.
type OpnsenseWireGuardClient struct {
	UUID          string `json:"uuid"`
	Name          string `json:"name,omitempty"`
	Enabled       bool   `json:"enabled"`
	Pubkey        string `json:"pubkey,omitempty"`
	TunnelAddress string `json:"tunnel_address,omitempty"`
	Server        string `json:"server,omitempty"`
	AllowedIPs    string `json:"allowed_ips,omitempty"`
}

// OpnsenseWireGuardStatus is whether the WireGuard service is running.
type OpnsenseWireGuardStatus struct {
	Running bool `json:"running"`
}

// ListWireGuardServers returns configured WireGuard server instances.
func (s *OpnsenseService) ListWireGuardServers(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseWireGuardServer, error) {
	got, err := s.client(opts).GetWireGuardServers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]OpnsenseWireGuardServer, len(got))
	for i, x := range got {
		out[i] = OpnsenseWireGuardServer{
			UUID: x.UUID, Name: x.Name, Enabled: x.Enabled,
			TunnelAddress: x.TunnelAddress, ListenPort: x.ListenPort, Peers: x.Peers,
		}
	}
	return out, nil
}

// ListWireGuardClients returns configured WireGuard peers.
func (s *OpnsenseService) ListWireGuardClients(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseWireGuardClient, error) {
	got, err := s.client(opts).GetWireGuardClients(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]OpnsenseWireGuardClient, len(got))
	for i, x := range got {
		out[i] = OpnsenseWireGuardClient{
			UUID: x.UUID, Name: x.Name, Enabled: x.Enabled, Pubkey: x.Pubkey,
			TunnelAddress: x.TunnelAddress, Server: x.Server, AllowedIPs: x.AllowedIPs,
		}
	}
	return out, nil
}

// GetWireGuardStatus returns whether the WireGuard service reports as running.
func (s *OpnsenseService) GetWireGuardStatus(ctx context.Context, opts OpnsenseOptions) (*OpnsenseWireGuardStatus, error) {
	got, err := s.client(opts).GetWireGuardStatus(ctx)
	if err != nil {
		return nil, err
	}
	return &OpnsenseWireGuardStatus{Running: got.Running}, nil
}
