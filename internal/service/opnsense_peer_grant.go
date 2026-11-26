package service

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/jpvelasco/nyx/internal/providers/opnsense"
)

const PeerApprovalEnv = "NYX_WIREGUARD_PEER_APPROVAL"

// A local operator prepares one file and configures its path on the Nyx process. MCP accepts no file, network, key or endpoint arguments.
type ApprovedPeer struct {
	Profile         string   `json:"profile"`
	CACertPath      string   `json:"ca_cert_path,omitempty"`
	Host            string   `json:"host"`
	UUID            string   `json:"uuid,omitempty"`
	Name            string   `json:"name"`
	PublicKey       string   `json:"public_key"`
	Servers         []string `json:"servers"`
	AllowedNetworks []string `json:"allowed_networks"`
	Enabled         *bool    `json:"enabled"`
}

var validPeerName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

func LoadApprovedPeer(path string) (ApprovedPeer, error) {
	var a ApprovedPeer
	// #nosec G304 -- only an operator configures the file path in the Nyx process environment.
	f, err := os.Open(path)
	if err != nil {
		return a, errors.New("set NYX_WIREGUARD_PEER_APPROVAL to an operator-prepared peer file")
	}
	defer f.Close()
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() > 16*1024 {
		return a, errors.New("invalid peer approval file")
	}
	dec := json.NewDecoder(io.LimitReader(f, 16*1024+1))
	dec.DisallowUnknownFields()
	if dec.Decode(&a) != nil || dec.Decode(new(any)) != io.EOF {
		return a, errors.New("invalid peer approval document")
	}
	return a, nil
}
func (a ApprovedPeer) desired() (opnsense.SelectedPeer, error) {
	key, err := base64.StdEncoding.DecodeString(a.PublicKey)
	if err != nil || len(key) != 32 || a.Profile == "" || a.Host == "" || !validPeerName.MatchString(a.Name) || a.Enabled == nil || len(a.Servers) == 0 || len(a.AllowedNetworks) == 0 || a.UUID != "" && !opnsense.ValidPeerUUID(a.UUID) {
		return opnsense.SelectedPeer{}, errors.New("incomplete approved peer identity or networks")
	}
	servers := slices.Clone(a.Servers)
	slices.Sort(servers)
	for i, id := range servers {
		if !opnsense.ValidPeerUUID(id) || i > 0 && servers[i-1] == id {
			return opnsense.SelectedPeer{}, errors.New("approved server UUIDs must be unique")
		}
	}
	nets, err := peerPrefixes(a.AllowedNetworks)
	if err != nil {
		return opnsense.SelectedPeer{}, err
	}
	return opnsense.SelectedPeer{Name: a.Name, PublicKey: a.PublicKey, Enabled: *a.Enabled, Networks: prefixStrings(nets), Servers: servers}, nil
}
func (a ApprovedPeer) locate(ctx context.Context, c *opnsense.Client) (string, error) {
	peers, err := c.WireGuardPeersForChange(ctx)
	if err != nil {
		return "", errors.New("cannot verify peer identities")
	}
	found := ""
	for _, p := range peers {
		if p.Pubkey == "" || p.Name == "" {
			return "", errors.New("incomplete peer identity inventory")
		}
		if p.UUID == a.UUID || p.Pubkey == a.PublicKey || strings.EqualFold(p.Name, a.Name) {
			if found != "" || p.Pubkey != a.PublicKey || p.Name != a.Name || a.UUID != "" && p.UUID != a.UUID {
				return "", errors.New("peer identity conflicts with operator approval")
			}
			found = p.UUID
		}
	}
	if a.UUID != "" && found == "" {
		return "", errors.New("approved peer UUID no longer exists")
	}
	return found, nil
}
func peerMatches(current, desired opnsense.SelectedPeer) bool {
	nets, err := peerPrefixes(current.Networks)
	return err == nil && current.PublicKey == desired.PublicKey && current.Name == desired.Name && current.Enabled == desired.Enabled && slices.Equal(current.Servers, desired.Servers) && slices.Equal(prefixStrings(nets), desired.Networks)
}

// ApplyApprovedPeer reconciles one exact operator-prepared record and verifies the result with a fresh UUID read.
func (s *OpnsenseService) ApplyApprovedPeer(ctx context.Context, opts OpnsenseOptions, a ApprovedPeer, dry bool) (*WireGuardPeerPlan, error) {
	opts.CACertPath = a.CACertPath
	d, err := a.desired()
	if err != nil {
		return nil, err
	}
	if opts.Host != a.Host {
		return nil, errors.New("approved firewall differs from the configured profile")
	}
	c := s.client(opts)
	id, err := a.locate(ctx, c)
	if err != nil {
		return nil, err
	}
	servers, err := c.GetWireGuardServers(ctx)
	if err != nil {
		return nil, errors.New("cannot verify approved server inventory")
	}
	for _, id := range d.Servers {
		if !slices.ContainsFunc(servers, func(s opnsense.WireGuardServer) bool { return s.UUID == id }) {
			return nil, errors.New("approved server does not exist")
		}
	}
	req := WireGuardPeerRequest{Action: "create", Name: a.Name, AllowedNetworks: d.Networks}
	if id != "" {
		req.Action, req.UUID = "update", id
	}
	plan, err := s.PlanWireGuardPeer(ctx, opts, req)
	if err != nil {
		return nil, err
	}
	if len(plan.Overlaps) > 0 || len(plan.Unverified) > 0 {
		return plan, errors.New("resolve peer network overlap or incomplete evidence before applying")
	}
	plan.OperatorAction = false
	plan.Outcome = "planned"
	matched := false
	if id != "" {
		cur, err := c.SelectedPeer(ctx, id)
		if err != nil || cur.PublicKey != d.PublicKey || cur.Name != d.Name {
			return plan, errors.New("cannot verify approved peer identity")
		}
		matched = peerMatches(cur, d)
		if matched {
			plan.Outcome = "unchanged"
		}
	}
	if dry {
		return plan, nil
	}
	if !matched {
		id, err = c.SaveSelectedPeer(ctx, id, d)
		if err != nil {
			return plan, errors.New("peer save unconfirmed; observe the approved peer before retrying")
		}
		plan.ConfigChanged = true
	}
	plan.UUID = id
	if err := c.ReloadWireGuard(ctx); err != nil {
		return plan, errors.New("WireGuard reload unconfirmed")
	}
	plan.Reloaded = true
	cur, err := c.SelectedPeer(ctx, id)
	if err != nil || !peerMatches(cur, d) {
		return plan, errors.New("approved peer readback differs")
	}
	plan.Verified = true
	status, err := c.GetWireGuardStatus(ctx)
	if err != nil {
		return plan, errors.New("peer verified; service status unavailable")
	}
	plan.ServiceRunning = &status.Running
	if !matched {
		plan.Outcome = "applied"
	}
	return plan, nil
}
