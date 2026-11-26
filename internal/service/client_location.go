package service

import (
	"context"
	"errors"
	"net"

	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/topology"
)

const ClientLocationCommand = "locate-client"
const ClientLocationTool = providers.ClientLocationCapability

func (*TopologyService) LocateClient(ctx context.Context, opts NetworkMapOptions, selector string) (topology.ClientLocation, error) {
	mac, err := net.ParseMAC(selector)
	if err != nil || len(mac) != 6 || mac[0]&1 != 0 || mac.String() == "00:00:00:00:00:00" {
		return topology.ClientLocation{}, errors.New("client selector must be a unicast MAC address")
	}
	inputs, err := collectMapInputs(ctx, opts, mac.String())
	if err != nil {
		return topology.ClientLocation{}, err
	}
	return topology.LocateClient(inputs, opts.Detail), nil
}
