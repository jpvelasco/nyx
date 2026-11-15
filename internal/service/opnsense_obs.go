package service

import (
	"context"

	opnsensebackend "github.com/jpvelasco/nyx/internal/providers/opnsense"
)

// OpnsenseInterface is a firewall interface with its IP configuration.
type OpnsenseInterface struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	DHCP        bool     `json:"dhcp"`
	IP          string   `json:"ip"`
	Subnet      int      `json:"subnet"`
	Gateway     string   `json:"gateway"`
	Device      string   `json:"device,omitempty"`
	MAC         string   `json:"mac,omitempty"`
	LinkType    string   `json:"link_type,omitempty"`
	Enabled     bool     `json:"enabled,omitempty"`
	MTU         int      `json:"mtu,omitempty"`
	Members     []string `json:"members,omitempty"`
	RxPackets   uint64   `json:"rx_packets,omitempty"`
	RxBytes     uint64   `json:"rx_bytes,omitempty"`
	TxPackets   uint64   `json:"tx_packets,omitempty"`
	TxBytes     uint64   `json:"tx_bytes,omitempty"`
}

// OpnsenseServiceStatus is one controller service (name + running).
type OpnsenseServiceStatus struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Running     bool   `json:"running"`
}

// OpnsenseGatewayStatus is one gateway health row.
type OpnsenseGatewayStatus struct {
	Name    string `json:"name"`
	Address string `json:"address,omitempty"`
	Status  string `json:"status"`
	Delay   string `json:"delay,omitempty"`
	StdDev  string `json:"stddev,omitempty"`
	Loss    string `json:"loss,omitempty"`
}

// OpnsenseBridge is one configured bridge and its members.
type OpnsenseBridge struct {
	UUID        string   `json:"uuid"`
	Description string   `json:"description,omitempty"`
	Members     []string `json:"members,omitempty"`
	STP         bool     `json:"stp,omitempty"`
}

// OpnsenseIfSetting is one configured interface from interfaces/settings/get.
type OpnsenseIfSetting struct {
	Name        string `json:"name"`
	Device      string `json:"device,omitempty"`
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`
	IPv4        string `json:"ipv4,omitempty"`
	Subnet      string `json:"subnet,omitempty"`
}

// OpnsensePfStatistics is the pf state-table summary.
type OpnsensePfStatistics struct {
	StateCount  int `json:"state_count"`
	SourceCount int `json:"source_count,omitempty"`
	Limit       int `json:"limit,omitempty"`
}

// OpnsenseKernelRoute is one kernel routing-table row.
type OpnsenseKernelRoute struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway,omitempty"`
	Netif       string `json:"netif,omitempty"`
	Flags       string `json:"flags,omitempty"`
}

// ListInterfaces returns the firewall interfaces with IP configuration.
func (s *OpnsenseService) ListInterfaces(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseInterface, error) {
	client := s.client(opts)
	ifaces, err := client.GetInterfaces(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]OpnsenseInterface, 0, len(ifaces))
	for _, i := range ifaces {
		out = append(out, flattenInterface(i))
	}
	return out, nil
}

// ListServices returns the controller service table (name + running).
func (s *OpnsenseService) ListServices(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseServiceStatus, error) {
	client := s.client(opts)
	svcs, err := client.GetServices(ctx)
	if err != nil {
		return nil, err
	}
	return flattenServices(svcs), nil
}

// ListGateways returns the gateway health table.
func (s *OpnsenseService) ListGateways(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseGatewayStatus, error) {
	client := s.client(opts)
	gws, err := client.GetGatewayStatus(ctx)
	if err != nil {
		return nil, err
	}
	return flattenGateways(gws), nil
}

func flattenInterface(i opnsensebackend.Interface) OpnsenseInterface {
	return OpnsenseInterface{
		Name:        i.Name,
		Description: i.Description,
		DHCP:        i.DHCP,
		IP:          i.IP,
		Subnet:      i.Subnet,
		Gateway:     i.Gateway,
		Device:      i.Device,
		MAC:         i.MAC,
		LinkType:    i.LinkType,
		Enabled:     i.Enabled,
		MTU:         i.MTU,
		Members:     i.Members,
		RxPackets:   i.RxPackets,
		RxBytes:     i.RxBytes,
		TxPackets:   i.TxPackets,
		TxBytes:     i.TxBytes,
	}
}

func flattenServices(in []opnsensebackend.Service) []OpnsenseServiceStatus {
	if len(in) == 0 {
		return nil
	}
	out := make([]OpnsenseServiceStatus, len(in))
	for i, s := range in {
		out[i] = OpnsenseServiceStatus{Name: s.Name, Description: s.Description, Running: s.Running}
	}
	return out
}

func flattenGateways(in []opnsensebackend.GatewayStatus) []OpnsenseGatewayStatus {
	if len(in) == 0 {
		return nil
	}
	out := make([]OpnsenseGatewayStatus, len(in))
	for i, g := range in {
		out[i] = OpnsenseGatewayStatus{
			Name: g.Name, Address: g.Address, Status: g.Status,
			Delay: g.Delay, StdDev: g.StdDev, Loss: g.Loss,
		}
	}
	return out
}

// ListBridges returns configured bridges and their members.
func (s *OpnsenseService) ListBridges(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseBridge, error) {
	client := s.client(opts)
	got, err := client.GetBridgeSettings(ctx)
	if err != nil {
		return nil, err
	}
	return flattenBridges(got), nil
}

// ListInterfaceSettings returns the per-interface config map.
func (s *OpnsenseService) ListInterfaceSettings(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseIfSetting, error) {
	client := s.client(opts)
	got, err := client.GetInterfaceSettings(ctx)
	if err != nil {
		return nil, err
	}
	return flattenIfSettings(got), nil
}

// GetPfStatistics returns the pf state-table summary.
func (s *OpnsenseService) GetPfStatistics(ctx context.Context, opts OpnsenseOptions) (*OpnsensePfStatistics, error) {
	client := s.client(opts)
	got, err := client.GetPfStatistics(ctx)
	if err != nil {
		return nil, err
	}
	return flattenPf(got), nil
}

// ListKernelRoutes returns the kernel routing table.
func (s *OpnsenseService) ListKernelRoutes(ctx context.Context, opts OpnsenseOptions) ([]OpnsenseKernelRoute, error) {
	client := s.client(opts)
	got, err := client.GetKernelRoutes(ctx)
	if err != nil {
		return nil, err
	}
	return flattenRoutes(got), nil
}

func flattenBridges(in []opnsensebackend.Bridge) []OpnsenseBridge {
	if len(in) == 0 {
		return nil
	}
	out := make([]OpnsenseBridge, len(in))
	for i, b := range in {
		out[i] = OpnsenseBridge{UUID: b.UUID, Description: b.Description, Members: b.Members, STP: b.STP}
	}
	return out
}

func flattenIfSettings(in []opnsensebackend.InterfaceSetting) []OpnsenseIfSetting {
	if len(in) == 0 {
		return nil
	}
	out := make([]OpnsenseIfSetting, len(in))
	for i, s := range in {
		out[i] = OpnsenseIfSetting{Name: s.Name, Device: s.Device, Description: s.Description, Enabled: s.Enabled, IPv4: s.IPv4, Subnet: s.Subnet}
	}
	return out
}

func flattenPf(in *opnsensebackend.PfStatistics) *OpnsensePfStatistics {
	if in == nil {
		return nil
	}
	return &OpnsensePfStatistics{StateCount: in.StateCount, SourceCount: in.SourceCount, Limit: in.Limit}
}

func flattenRoutes(in []opnsensebackend.KernelRoute) []OpnsenseKernelRoute {
	if len(in) == 0 {
		return nil
	}
	out := make([]OpnsenseKernelRoute, len(in))
	for i, r := range in {
		out[i] = OpnsenseKernelRoute{Destination: r.Destination, Gateway: r.Gateway, Netif: r.Netif, Flags: r.Flags}
	}
	return out
}
