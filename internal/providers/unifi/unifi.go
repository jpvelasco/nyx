// Package unifi reads the official local Network integration API on a UniFi OS console.
package unifi

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jpvelasco/nyx/internal/credentials"
	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/topology"
)

type Adapter struct{}

func (Adapter) Name() string           { return "unifi" }
func (Adapter) Capabilities() []string { return []string{providers.NetworkMapCapability} }
func (Adapter) CredentialFields() []credentials.Field {
	return []credentials.Field{
		{Name: "host", Env: "UNIFI_HOST", Required: true, Description: "UniFi OS HTTPS console origin"},
		{Name: "api_key", Env: "UNIFI_API_KEY", Required: true, Secret: true, Description: "Local Network integration API key"},
		{Name: "site", Env: "UNIFI_SITE", Description: "Site ID or unique site name"},
	}
}
func init() {
	if err := providers.Register(Adapter{}); err != nil {
		panic(err)
	}
}

type client struct {
	base, key string
	http      *http.Client
}

func newClient(opts providers.ImportOptions) (*client, error) {
	host := opts.Host
	if !strings.Contains(host, "://") {
		host = "https://" + host
	}
	base, err := url.Parse(host)
	if err != nil || base.Scheme != "https" || base.Hostname() == "" || base.User != nil ||
		base.RawQuery != "" || base.Fragment != "" || strings.Trim(base.EscapedPath(), "/") != "" {
		return nil, errors.New("UniFi requires the HTTPS origin of the local console")
	}
	if opts.Credentials["api_key"] == "" {
		return nil, errors.New("UniFi integration key is required")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: opts.SkipTLSVerify} // #nosec G402 -- explicit per-connection TLS option for private consoles
	if opts.CACertPath != "" {
		pem, err := os.ReadFile(opts.CACertPath) // #nosec G304 -- operator-selected CA file
		if err != nil {
			return nil, errors.New("cannot read the UniFi CA file")
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("invalid UniFi CA file")
		}
		config.RootCAs = pool
		config.InsecureSkipVerify = false
	}
	return &client{
		base: "https://" + base.Host + "/proxy/network/integration/v1",
		key:  opts.Credentials["api_key"],
		http: &http.Client{
			Timeout: 15 * time.Second, Transport: &http.Transport{TLSClientConfig: config},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

type statusError int

func (e statusError) HTTPStatus() int { return int(e) }
func (e statusError) Error() string {
	return fmt.Sprintf("UniFi integration request returned HTTP %d", int(e))
}

func (c *client) read(ctx context.Context, path string, dest any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return errors.New("invalid UniFi integration request")
	}
	req.Header.Set("X-API-Key", c.key)
	req.Header.Set("Accept", "application/json")
	res, err := c.http.Do(req) // #nosec G704 -- trusted configured console origin and fixed integration paths; redirects disabled
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("UniFi integration request failed")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return statusError(res.StatusCode)
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(dest); err != nil {
		return errors.New("invalid UniFi integration response")
	}
	return nil
}

type identity struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	MAC      string   `json:"macAddress"`
	Features []string `json:"features"`
}

func (c *client) inventory(ctx context.Context, path string) ([]identity, error) {
	var all []identity
	seen := map[string]bool{}
	total := -1
	for offset := 0; ; {
		var page struct {
			Offset, Count, TotalCount *int
			Data                      []identity
		}
		if err := c.read(ctx, path+"?limit=100&offset="+strconv.Itoa(offset), &page); err != nil {
			return nil, err
		}
		if page.Offset == nil || *page.Offset != offset || page.Count == nil || *page.Count != len(page.Data) ||
			page.TotalCount == nil || page.Data == nil || *page.TotalCount < offset+len(page.Data) ||
			(total >= 0 && total != *page.TotalCount) {
			return nil, errors.New("incomplete or changing UniFi inventory")
		}
		total = *page.TotalCount
		for _, row := range page.Data {
			row.ID = strings.ToLower(row.ID)
			if err := uuid.Validate(row.ID); err != nil || len(row.ID) != 36 || seen[row.ID] {
				return nil, errors.New("invalid or repeated UniFi inventory identity")
			}
			seen[row.ID] = true
			all = append(all, row)
		}
		offset += len(page.Data)
		if offset == total {
			return all, nil
		}
		if len(page.Data) == 0 {
			return nil, errors.New("incomplete UniFi inventory")
		}
	}
}
func siteFor(sites []identity, name string) (identity, error) {
	if name == "" {
		if len(sites) == 1 {
			return sites[0], nil
		}
		return identity{}, errors.New("select a configured UniFi site by name or ID")
	}
	var site identity
	for _, candidate := range sites {
		if strings.EqualFold(candidate.ID, name) || strings.EqualFold(candidate.Name, name) {
			if site.ID != "" {
				return identity{}, errors.New("ambiguous UniFi site; select the site ID")
			}
			site = candidate
		}
	}
	if site.ID == "" {
		return site, errors.New("select a configured UniFi site by name or ID")
	}
	return site, nil
}
func deviceRef(d identity) topology.ResourceRef {
	kind := "device"
	switch {
	case slices.Contains(d.Features, "gateway"):
		kind = "gateway"
	case slices.Contains(d.Features, "accessPoint"):
		kind = "ap"
	case slices.Contains(d.Features, "switching"):
		kind = "switch"
	}
	return topology.ResourceRef{Kind: kind, Key: d.ID}
}
func (Adapter) ObserveNetwork(ctx context.Context, opts providers.ImportOptions) (topology.ObservationSet, error) {
	var facts topology.ObservationSet
	c, err := newClient(opts)
	if err != nil {
		return facts, err
	}
	defer c.http.CloseIdleConnections()
	sites, err := c.inventory(ctx, "/sites")
	if err != nil {
		return facts, err
	}
	site, err := siteFor(sites, opts.Site)
	if err != nil {
		return facts, err
	}
	facts.ControllerSite = site.Name
	path := "/sites/" + site.ID + "/devices"
	devices, err := c.inventory(ctx, path)
	if err != nil {
		return facts, err
	}
	byID := make(map[string]topology.ResourceRef, len(devices))
	for _, d := range devices {
		ref := deviceRef(d)
		byID[d.ID] = ref
		facts.Resources = append(facts.Resources, topology.Observation{Ref: ref, Name: d.Name, MAC: d.MAC})
	}
	gaps := map[string]bool{}
	for _, d := range devices {
		var detail struct {
			ID         string
			Interfaces struct{ Ports []struct{ Idx int } }
			Uplink     *struct{ DeviceID string }
		}
		if err := c.read(ctx, path+"/"+d.ID, &detail); err != nil || !strings.EqualFold(detail.ID, d.ID) {
			if ctx.Err() != nil {
				return facts, ctx.Err()
			}
			gaps["device details"] = true
			continue
		}
		ref := byID[d.ID]
		if ref.Kind == "switch" && detail.Interfaces.Ports == nil {
			gaps["port inventory"] = true
		}
		ports := map[int]bool{}
		for _, p := range detail.Interfaces.Ports {
			if p.Idx <= 0 || ports[p.Idx] {
				gaps["port identity"] = true
				continue
			}
			ports[p.Idx] = true
			port := topology.ResourceRef{Kind: "port", Key: d.ID + "/" + strconv.Itoa(p.Idx)}
			facts.Resources = append(facts.Resources, topology.Observation{Ref: port, Port: p.Idx})
			facts.Links = append(facts.Links, topology.LinkObservation{From: port, To: topology.MapTarget{Ref: ref}, Relation: "device", Evidence: "UniFi port inventory"})
		}
		if detail.Uplink != nil {
			if parent, ok := byID[strings.ToLower(detail.Uplink.DeviceID)]; ok && parent != ref {
				facts.Links = append(facts.Links, topology.LinkObservation{From: ref, To: topology.MapTarget{Ref: parent}, Relation: "uplink", Evidence: "UniFi managed uplink"})
			} else {
				gaps["uplink peer"] = true
			}
		}
	}
	// The published interface summary has no external LLDP peer or port VLAN fields.
	facts.Gaps = append(facts.Gaps, "external link neighbors", "port VLAN membership")
	for name := range gaps {
		facts.Gaps = append(facts.Gaps, name)
	}
	slices.Sort(facts.Gaps)
	return facts, nil
}
