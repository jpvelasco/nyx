package service

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/jpvelasco/nyx/internal/credentials"
	"github.com/jpvelasco/nyx/internal/providers"
)

const CapabilitiesCommand = "capabilities"
const CapabilitiesTool = "provider_capabilities"

// CapabilityOptions selects configured connections. Observe reads only controller information.
type CapabilityOptions struct {
	Provider, Profile      string
	Observe, SkipTLSVerify bool
	CACertPath             string
}

type ConnectionCapabilities struct {
	credentials.ConnectionInfo
	InfoAccess string `json:"info_access"`
}

type ProviderCapabilities struct {
	Provider         string                   `json:"provider"`
	Operations       []string                 `json:"operations"`
	CredentialFields []credentials.Field      `json:"credential_fields"`
	Connections      []ConnectionCapabilities `json:"connections"`
}

// ProviderCapabilityReport enumerates adapter support offline. An observation applies only to the info read.
func ProviderCapabilityReport(ctx context.Context, opts CapabilityOptions, path string, getenv func(string) string) ([]ProviderCapabilities, error) {
	adapters := providers.Adapters()
	if opts.Provider != "" {
		p, ok := providers.LookupAdapter(opts.Provider)
		if !ok {
			return nil, fmt.Errorf("unknown provider %q", opts.Provider)
		}
		adapters = []providers.Adapter{p}
	}
	if getenv == nil {
		getenv = os.Getenv
	}
	byProvider := map[string][]credentials.ConnectionInfo{}
	// An absent credential store is normal for environment-only connections. Listing must not create it.
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		store, err := credentials.Open(path)
		if err != nil {
			return nil, fmt.Errorf("opening credential store: %w", err)
		}
		for _, c := range store.Connections() {
			byProvider[c.Provider] = append(byProvider[c.Provider], c)
		}
	}
	result := make([]ProviderCapabilities, 0, len(adapters))
	for _, adapter := range adapters {
		name := adapter.Name()
		fields := credentials.FieldsFor(name)
		entry := ProviderCapabilities{Provider: name, Operations: slices.Clone(adapter.Capabilities()), CredentialFields: fields, Connections: []ConnectionCapabilities{}}
		op, hasInfo := ControllerInfo(adapter)
		conns := byProvider[name]
		defaultIndex := slices.IndexFunc(conns, func(c credentials.ConnectionInfo) bool { return c.ProfileName() == "default" })
		// Resolve default routing from the environment before using store site labels.
		envDefault := credentials.ConnectionInfo{Connection: credentials.Connection{Provider: name, Profile: "default"}}
		env := credentials.Resolve(credentials.Connection{Provider: name}, nil, getenv, "", false)
		if env["host"] != "" || env["site"] != "" {
			if defaultIndex >= 0 {
				actual := credentials.Resolve(envDefault.Connection, nil, getenv, path, false)
				conns[defaultIndex].Site = actual["site"]
				conns[defaultIndex].LogicalSite = actual["logical_site"]
			} else if env["host"] != "" {
				envDefault.Site = env["site"]
				conns = append(conns, envDefault)
				slices.SortFunc(conns, func(a, b credentials.ConnectionInfo) int { return strings.Compare(a.Profile, b.Profile) })
			}
		}
		for _, c := range conns {
			if opts.Profile != "" && opts.Profile != c.ProfileName() {
				continue
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			entry.Connections = append(entry.Connections, observeConnection(ctx, op, hasInfo, c, opts, path, getenv))
			if err := ctx.Err(); err != nil {
				return nil, err
			}
		}
		result = append(result, entry)
	}
	return result, nil
}

func observeConnection(ctx context.Context, op InfoOperation, hasInfo bool, c credentials.ConnectionInfo, opts CapabilityOptions, path string, getenv func(string) string) ConnectionCapabilities {
	entry := ConnectionCapabilities{ConnectionInfo: c, InfoAccess: "unverified"}
	if !hasInfo {
		entry.InfoAccess = "unsupported"
		return entry
	}
	if !opts.Observe {
		return entry
	}
	fields := credentials.Resolve(c.Connection, nil, getenv, path, op.Authenticated)
	if fields["host"] == "" || op.Authenticated && c.Require(fields) != nil {
		entry.InfoAccess = "missing_credentials"
		return entry
	}
	input := providers.ConnectionOptions(c.Connection, fields)
	input.SkipTLSVerify = opts.SkipTLSVerify
	input.CACertPath = opts.CACertPath
	_, err := op.Read(ctx, input)
	entry.InfoAccess = readAccess(err)
	return entry
}

// DiagnosticAccess classifies read outcomes without exposing URLs, credentials or device messages.
func DiagnosticAccess(err error) string {
	return readAccess(err)
}

func readAccess(err error) string {
	if err == nil {
		return "observed"
	}
	var status interface{ HTTPStatus() int }
	if errors.As(err, &status) {
		switch status.HTTPStatus() {
		case http.StatusForbidden:
			return "permission_denied"
		case http.StatusUnauthorized:
			return "authentication_failed"
		case http.StatusNotFound:
			return "unsupported"
		}
	}
	return "unavailable"
}
