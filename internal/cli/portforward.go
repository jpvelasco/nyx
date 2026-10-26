package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/jpvelasco/nyx/internal/credentials"
	"github.com/jpvelasco/nyx/internal/credentials/credmanager"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/jpvelasco/nyx/internal/storepath"
	"github.com/spf13/cobra"
)

var (
	pfExternalPort      string
	pfTarget            string
	pfLocalPort         string
	pfProtocol          string
	pfLabel             string
	pfApply             bool
	pfDryRun            bool
	pfOmadaHost         string
	pfOmadaClientID     string
	pfOmadaClientSecret string
	pfOmadaSite         string
	pfOpnsenseHost      string
	pfOpnsenseAPIKey    string
	pfOpnsenseAPISecret string
	pfSkipTLSVerify     bool
	pfCACertPath        string
)

// portForwardCmd is the composed port-forward playbook (#140): it
// observes the topology, selects the backend that owns the egress-path
// NAT, and plans (default) or applies the rule through that backend.
var portForwardCmd = &cobra.Command{
	Use:   "port-forward",
	Short: "Plan or apply a port-forward on the backend that owns the egress NAT",
	Long: `Composed playbook: plan (default) or apply a port-forward rule on the
backend that owns the egress-path NAT.

The command observes the NAT topology first (nyx topology), selects the
on-path NAT router, and defers to that backend's plan/apply surface:

- OPNsense owns NAT: the plan previews the rule; --apply creates it
  (dry-run by default; pass --apply --dry-run=false for the real write).
- The managed Omada gateway owns NAT: the playbook reports the honest
  hold — the Omada Open API exposes no live-site NAT write path, so the
  rule must be configured via the controller UI.
- Double-NAT or indeterminate topologies refuse with an explanation.

Credentials for omada and/or opnsense resolve like every other command:
flags, environment variables, Windows Credential Manager, or the
credential store.`,
	Example: `  nyx port-forward --port 443 --target 10.0.40.10
  nyx port-forward --port 443 --target 10.0.40.10 --local-port 8443 --protocol tcp --label web
  nyx port-forward --port 443 --target 10.0.40.10 --apply                  # dry-run apply
  nyx port-forward --port 443 --target 10.0.40.10 --apply --dry-run=false   # real apply`,
	RunE: func(_ *cobra.Command, _ []string) error {
		dur, err := parseTimeoutFlag(timeout)
		if err != nil {
			return err
		}
		if dur == 0 {
			dur = 120 * time.Second
		}
		ctx, cancel := context.WithTimeout(context.Background(), dur)
		defer cancel()

		req := service.PortForwardRequest{
			ExternalPort: pfExternalPort,
			Target:       pfTarget,
			LocalPort:    pfLocalPort,
			Protocol:     pfProtocol,
			Label:        pfLabel,
		}
		if err := req.Validate(); err != nil {
			return err
		}

		omadaOpts, err := resolvePlaybookOmadaOpts()
		if err != nil {
			return err
		}
		opnsOpts, err := resolvePlaybookOpnsenseOpts()
		if err != nil {
			return err
		}
		if omadaOpts == nil && opnsOpts == nil {
			return fmt.Errorf("the port-forward playbook needs a host for at least one provider: " +
				"pass --omada-host or --opnsense-host, set OMADA_HOST / OPNSENSE_HOST, " +
				"or run `nyx credentials set <provider> --set host=...`")
		}

		pbOpts := service.PlaybookOptions{Omada: omadaOpts, Opnsense: opnsOpts}
		svc := service.NewPlaybookService(service.NewTopologyService())
		if !pfApply {
			plan, err := svc.PlanPortForward(ctx, pbOpts, req)
			if err != nil {
				return err
			}
			renderPortForwardPlan(plan)
			return nil
		}
		res, err := svc.ApplyPortForward(ctx, pbOpts, req, pfDryRun)
		if err != nil {
			return err
		}
		renderPortForwardPlan(res)
		if res.Outcome == "refused" {
			return fmt.Errorf("port-forward refused: %s", res.Playbook)
		}
		return nil
	},
}

// renderPortForwardPlan prints the composed plan: the routing decision
// trail, then the delegated outcome with warnings.
func renderPortForwardPlan(p *service.PortForwardPlan) {
	fmt.Printf("playbook: %s\n", p.Playbook)
	fmt.Printf("provider: %s (decision: %s, topology risk: %s)\n", p.Provider, p.Decision, p.Risk)
	fmt.Printf("outcome: %s", p.Outcome)
	if p.RuleUUID != "" {
		fmt.Printf(" (rule %s)", p.RuleUUID)
	}
	fmt.Println()
	for _, w := range p.Warnings {
		fmt.Printf("warning: %s\n", w)
	}
}

// resolvePlaybookOmadaOpts resolves the Omada credential set with the
// standard chain (flags → env → Credential Manager → store), mirroring
// the topology command.
func resolvePlaybookOmadaOpts() (*service.OmadaOptions, error) {
	opts := service.OmadaOptions{
		Host:          firstNonEmptyCLI(pfOmadaHost, os.Getenv("OMADA_HOST")),
		ClientID:      firstNonEmptyCLI(pfOmadaClientID, os.Getenv("OMADA_CLIENT_ID")),
		ClientSecret:  firstNonEmptyCLI(pfOmadaClientSecret, os.Getenv("OMADA_CLIENT_SECRET")),
		Site:          firstNonEmptyCLI(pfOmadaSite, os.Getenv("OMADA_SITE")),
		SkipTLSVerify: pfSkipTLSVerify,
		CACertPath:    pfCACertPath,
	}
	opts.ClientID, opts.ClientSecret = credmanager.OverlayOmada(opts.Host, opts.ClientID, opts.ClientSecret)
	if opts.Host == "" || opts.ClientID == "" || opts.ClientSecret == "" {
		fields := credentials.Fields{Host: opts.Host, ClientID: opts.ClientID, ClientSecret: opts.ClientSecret, Site: opts.Site}
		credentials.Overlay(storepath.StoreFile(), "omada", "default", &fields)
		opts.Host, opts.ClientID, opts.ClientSecret, opts.Site = fields.Host, fields.ClientID, fields.ClientSecret, fields.Site
	}
	if opts.Host == "" {
		return nil, nil
	}
	if opts.ClientID == "" || opts.ClientSecret == "" {
		return nil, fmt.Errorf("%s", "omada credentials incomplete: set --omada-client-id/--omada-client-secret, "+
			"OMADA_CLIENT_ID / OMADA_CLIENT_SECRET"+credmanager.Hint(opts.Host)+
			", or run `nyx credentials set omada`")
	}
	return &opts, nil
}

// resolvePlaybookOpnsenseOpts resolves the OPNsense credential set with
// the standard chain, mirroring the topology command.
func resolvePlaybookOpnsenseOpts() (*service.OpnsenseOptions, error) {
	opts := service.OpnsenseOptions{
		Host:          firstNonEmptyCLI(pfOpnsenseHost, os.Getenv("OPNSENSE_HOST")),
		APIKey:        firstNonEmptyCLI(pfOpnsenseAPIKey, os.Getenv("OPNSENSE_API_KEY")),
		APISecret:     firstNonEmptyCLI(pfOpnsenseAPISecret, os.Getenv("OPNSENSE_API_SECRET")),
		SkipTLSVerify: pfSkipTLSVerify,
		CACertPath:    pfCACertPath,
	}
	opts.APIKey, opts.APISecret = credmanager.OverlayOpnsense(opts.Host, opts.APIKey, opts.APISecret)
	if opts.Host == "" || opts.APIKey == "" || opts.APISecret == "" {
		fields := credentials.Fields{Host: opts.Host, APIKey: opts.APIKey, APISecret: opts.APISecret}
		credentials.Overlay(storepath.StoreFile(), "opnsense", "default", &fields)
		opts.Host, opts.APIKey, opts.APISecret = fields.Host, fields.APIKey, fields.APISecret
	}
	if opts.Host == "" {
		return nil, nil
	}
	if opts.APIKey == "" || opts.APISecret == "" {
		return nil, fmt.Errorf("%s", "opnsense credentials incomplete: set --opnsense-api-key/--opnsense-api-secret, "+
			"OPNSENSE_API_KEY / OPNSENSE_API_SECRET"+credmanager.HintOpnsense(opts.Host)+
			", or run `nyx credentials set opnsense`")
	}
	return &opts, nil
}

func firstNonEmptyCLI(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func init() {
	f := portForwardCmd.Flags()
	f.StringVar(&pfExternalPort, "port", "", "External (WAN) port or range to forward (required)")
	f.StringVar(&pfTarget, "target", "", "Internal LAN IP to forward to (required)")
	f.StringVar(&pfLocalPort, "local-port", "", "Forwarded internal port or range (default: same as --port)")
	f.StringVar(&pfProtocol, "protocol", "", "IP protocol (tcp, udp); empty = any")
	f.StringVar(&pfLabel, "label", "", "Rule name")
	f.BoolVar(&pfApply, "apply", false, "Apply through the selected backend (dry-run by default)")
	f.BoolVar(&pfDryRun, "dry-run", true, "Preview only (with --apply)")
	f.StringVar(&pfOmadaHost, "omada-host", "", "Omada controller IP or hostname (omit to skip Omada)")
	f.StringVar(&pfOmadaClientID, "omada-client-id", "", "Omada Open API client ID")
	f.StringVar(&pfOmadaClientSecret, "omada-client-secret", "", "Omada Open API client secret")
	f.StringVar(&pfOmadaSite, "omada-site", "", "Omada site name")
	f.StringVar(&pfOpnsenseHost, "opnsense-host", "", "OPNsense firewall IP or hostname (omit to skip OPNsense)")
	f.StringVar(&pfOpnsenseAPIKey, "opnsense-api-key", "", "OPNsense API key")
	f.StringVar(&pfOpnsenseAPISecret, "opnsense-api-secret", "", "OPNsense API secret")
	f.BoolVar(&pfSkipTLSVerify, "skip-tls-verify", false, "Skip TLS certificate verification (self-signed certs)")
	f.StringVar(&pfCACertPath, "ca-cert", "", "Path to custom CA certificate PEM file")
}
