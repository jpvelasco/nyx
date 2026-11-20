package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jpvelasco/nyx/internal/credentials"
	"github.com/jpvelasco/nyx/internal/credentials/credmanager"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/jpvelasco/nyx/internal/storepath"
	"github.com/jpvelasco/nyx/internal/topology"
	"github.com/spf13/cobra"
)

var (
	topoOmadaHost         string
	topoOmadaClientID     string
	topoOmadaClientSecret string
	topoOmadaSite         string
	topoOpnsenseHost      string
	topoOpnsenseAPIKey    string
	topoOpnsenseAPISecret string
	topoSkipTLSVerify     bool
	topoCACertPath        string
)

var topologyCmd = &cobra.Command{
	Use:   "topology",
	Short: "Assess network topology: per-device NAT role and double-NAT risk",
	Long: `Assess the network topology from the Omada and OPNsense providers' NAT
posture. For each observed device the command reports its NAT role
(nat_router / bridge / indeterminate / unknown) and a short evidence trail,
then a site-level double-NAT risk verdict.

The command is read-only: it issues only GETs. Configure credentials for
omada and/or opnsense (flags, environment variables, Windows Credential
Manager, or the credential store) to observe that provider; a provider
with no resolvable host is skipped. A host that is present but whose
credentials are incomplete is a hard error — a partial picture would
produce a confidently wrong verdict.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		dur, err := parseTimeoutFlag(timeout)
		if err != nil {
			return err
		}
		if dur == 0 {
			dur = 60 * time.Second
		}
		ctx, cancel := context.WithTimeout(cmd.Context(), dur)
		defer cancel()

		omadaOpts, err := resolveOmadaTopologyOpts()
		if err != nil {
			return err
		}
		opnsOpts, err := resolveOpnsenseTopologyOpts()
		if err != nil {
			return err
		}
		if omadaOpts == nil && opnsOpts == nil {
			return fmt.Errorf("topology needs a host for at least one provider: " +
				"pass --omada-host or --opnsense-host, set OMADA_HOST / OPNSENSE_HOST, " +
				"or run `nyx credentials set <provider> --set host=...`")
		}

		fingerprint, detail := topologyFingerprintFlags(cmd)
		rep, err := service.NewTopologyService().Report(ctx, service.TopologyOptions{
			Omada:       omadaOpts,
			Opnsense:    opnsOpts,
			Fingerprint: fingerprint,
			Detail:      detail,
		})
		if err != nil {
			return err
		}

		w, err := getWriter()
		if err != nil {
			return err
		}
		if outputPath != "" {
			defer w.Close()
		}
		if jsonOutput {
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			return enc.Encode(rep)
		}
		printTopologyReport(w, rep)
		return nil
	},
}

// resolveOmadaTopologyOpts returns the Omada options for the topology
// report, or nil when the host cannot be resolved after the flags ->
// env -> Credential Manager (nyx-omada-<host>, Windows) -> store chain
// (meaning: skip Omada). It returns a non-nil error when a host is
// present but the credentials are incomplete after all four layers.
func resolveOmadaTopologyOpts() (*service.OmadaOptions, error) {
	opts := service.OmadaOptions{
		Host:          storepath.FirstNonEmpty(topoOmadaHost, os.Getenv("OMADA_HOST")),
		ClientID:      storepath.FirstNonEmpty(topoOmadaClientID, os.Getenv("OMADA_CLIENT_ID")),
		ClientSecret:  storepath.FirstNonEmpty(topoOmadaClientSecret, os.Getenv("OMADA_CLIENT_SECRET")),
		Site:          storepath.FirstNonEmpty(topoOmadaSite, os.Getenv("OMADA_SITE")),
		SkipTLSVerify: topoSkipTLSVerify,
		CACertPath:    topoCACertPath,
	}
	// Windows Credential Manager layer, between env vars and the store
	// (no-op off Windows — see credmanager).
	opts.ClientID, opts.ClientSecret = credmanager.OverlayOmada(opts.Host, opts.ClientID, opts.ClientSecret)
	if opts.Host == "" || opts.ClientID == "" || opts.ClientSecret == "" {
		fields := credentials.Fields{
			Host:         opts.Host,
			ClientID:     opts.ClientID,
			ClientSecret: opts.ClientSecret,
			Site:         opts.Site,
		}
		credentials.Overlay(storepath.StoreFile(), "omada", "default", &fields)
		opts.Host, opts.ClientID, opts.ClientSecret, opts.Site = fields.Host, fields.ClientID, fields.ClientSecret, fields.Site
	}
	if opts.Host == "" {
		return nil, nil
	}
	if opts.ClientID == "" || opts.ClientSecret == "" {
		return nil, errors.New("omada credentials incomplete: set --omada-client-id/--omada-client-secret, " +
			"OMADA_CLIENT_ID / OMADA_CLIENT_SECRET" + credmanager.Hint(opts.Host) +
			", or run `nyx credentials set omada`")
	}
	return &opts, nil
}

// resolveOpnsenseTopologyOpts returns the OPNsense options for the topology
// report, or nil when the host cannot be resolved after the flags -> env ->
// Credential Manager (nyx-opnsense-<host>, Windows) -> store chain
// (meaning: skip OPNsense). It returns a non-nil error when a host is
// present but the credentials are incomplete after all four layers.
func resolveOpnsenseTopologyOpts() (*service.OpnsenseOptions, error) {
	opts := service.OpnsenseOptions{
		Host:          storepath.FirstNonEmpty(topoOpnsenseHost, os.Getenv("OPNSENSE_HOST")),
		APIKey:        storepath.FirstNonEmpty(topoOpnsenseAPIKey, os.Getenv("OPNSENSE_API_KEY")),
		APISecret:     storepath.FirstNonEmpty(topoOpnsenseAPISecret, os.Getenv("OPNSENSE_API_SECRET")),
		SkipTLSVerify: topoSkipTLSVerify,
		CACertPath:    topoCACertPath,
	}
	// Windows Credential Manager layer, between env vars and the store
	// (no-op off Windows — see credmanager).
	opts.APIKey, opts.APISecret = credmanager.OverlayOpnsense(opts.Host, opts.APIKey, opts.APISecret)
	if opts.Host == "" || opts.APIKey == "" || opts.APISecret == "" {
		fields := credentials.Fields{
			Host:      opts.Host,
			APIKey:    opts.APIKey,
			APISecret: opts.APISecret,
		}
		credentials.Overlay(storepath.StoreFile(), "opnsense", "default", &fields)
		opts.Host, opts.APIKey, opts.APISecret = fields.Host, fields.APIKey, fields.APISecret
	}
	if opts.Host == "" {
		return nil, nil
	}
	if opts.APIKey == "" || opts.APISecret == "" {
		return nil, errors.New("opnsense credentials incomplete: set --opnsense-api-key/--opnsense-api-secret, " +
			"OPNSENSE_API_KEY / OPNSENSE_API_SECRET" + credmanager.HintOpnsense(opts.Host) +
			", or run `nyx credentials set opnsense`")
	}
	return &opts, nil
}

// printTopologyReport renders the topology assessment for a human: the
// double-NAT verdict up front, the per-device roles with their evidence,
// then the raw per-provider NAT facts. An empty outbound-NAT mode is printed
// as "unknown" — the mode key may be absent (version drift) and must not be
// guessed.
func printTopologyReport(w io.Writer, rep *service.TopologyReport) {
	if rep.Fingerprint != nil {
		printTopologyFingerprint(w, rep.Fingerprint)
	}
	fmt.Fprintf(w, "Double-NAT risk: %s\n", rep.Risk)
	fmt.Fprintf(w, "Reason:          %s\n\n", rep.Reason)
	for _, d := range rep.Devices {
		fmt.Fprintf(w, "%s: %s\n", d.Provider, d.Role)
		for _, e := range d.Evidence {
			fmt.Fprintf(w, "  - %s\n", e)
		}
	}
	fmt.Fprintln(w)
	if rep.Omada != nil {
		fmt.Fprintln(w, "Omada:")
		fmt.Fprintf(w, "  site:               %s\n", rep.Omada.Site)
		fmt.Fprintf(w, "  managed gateway:    %t\n", rep.Omada.HasManagedGateway)
		fmt.Fprintf(w, "  port-forward rules: %d\n", rep.Omada.PortForwardRules)
		fmt.Fprintf(w, "  one-to-one rules:   %d\n", rep.Omada.OneToOneRules)
	}
	if rep.Opnsense != nil {
		fmt.Fprintln(w, "OPNsense:")
		mode := rep.Opnsense.OutboundNatMode
		if mode == "" {
			mode = "unknown"
		}
		fmt.Fprintf(w, "  outbound NAT mode:  %s\n", mode)
		fmt.Fprintf(w, "  source-NAT rules:   %d\n", len(rep.Opnsense.SourceNatRules))
		fmt.Fprintf(w, "  port-forward rules: %d\n", len(rep.Opnsense.PortForwardRules))
		fmt.Fprintf(w, "  one-to-one rules:   %d\n", len(rep.Opnsense.OneToOneRules))
	}
}

func printTopologyFingerprint(w io.Writer, fingerprint *topology.Fingerprint) {
	fmt.Fprintln(w, "Architecture fingerprint")
	if fingerprint.Edge != nil {
		fmt.Fprintf(w, "  %s\n", describeFingerprintEdge(*fingerprint.Edge))
	}
	for _, device := range fingerprint.Devices {
		fmt.Fprintf(w, "  %s: %s", device.Provider, device.Role)
		if device.ManagedUpstream != "" {
			fmt.Fprintf(w, " -> %s", device.ManagedUpstream)
		}
		fmt.Fprintln(w)
		if device.WhereToLook != "" {
			fmt.Fprintf(w, "    %s\n", device.WhereToLook)
		}
	}
	for _, segment := range fingerprint.Segments {
		gateway := segment.Gateway
		if gateway == "" {
			gateway = "unknown"
		}
		fmt.Fprintf(w, "  VLAN %d -> %s", segment.VLAN, gateway)
		if len(segment.ObservedBy) > 0 {
			fmt.Fprintf(w, " (seen by %s)", strings.Join(segment.ObservedBy, ", "))
		}
		fmt.Fprintln(w)
		if segment.Detail != nil {
			printSegmentDetail(w, *segment.Detail)
		}
	}
	for _, warning := range fingerprint.Warnings {
		fmt.Fprintf(w, "  Warning: %s\n", warning)
	}
	fmt.Fprintln(w)
}

// printSegmentDetail renders a segment's private addressing, shown only
// when the operator asked for --detail.
func printSegmentDetail(w io.Writer, detail topology.SegmentDetail) {
	fmt.Fprintf(w, "    subnet %s, gateway %s\n", detail.CIDR, detail.GatewayAddress)
	candidates := make([]string, 0, len(detail.ProbeCandidates))
	for _, c := range detail.ProbeCandidates {
		label := c.Address
		if c.Hostname != "" {
			label = c.Hostname + " " + c.Address
		}
		candidates = append(candidates, fmt.Sprintf("%s [%s]", label, c.Source))
	}
	if len(candidates) == 0 {
		candidates = []string{"none in inventory"}
	}
	fmt.Fprintf(w, "    probe candidates (unverified): %s\n", strings.Join(candidates, ", "))
}

// addTopologyFingerprintFlags registers the fingerprint flags.
func addTopologyFingerprintFlags(cmd *cobra.Command) {
	cmd.Flags().Bool("fingerprint", false, "Infer architecture from configured provider inventory without probing the network")
	cmd.Flags().Bool("detail", false, "With the fingerprint, also show each segment's subnet, gateway address, and inventory-known probe candidates (private: implies --fingerprint)")
}

// topologyFingerprintFlags reads the fingerprint flags; --detail implies
// --fingerprint.
func topologyFingerprintFlags(cmd *cobra.Command) (fingerprint, detail bool) {
	fingerprint, _ = cmd.Flags().GetBool("fingerprint")
	detail, _ = cmd.Flags().GetBool("detail")
	return fingerprint || detail, detail
}

// fingerprintNextHop explains each edge next-hop classification in words.
var fingerprintNextHop = map[string]string{
	topology.NextHopInternet:       "next hop is the internet, so this is the network edge",
	topology.NextHopUpstreamRouter: "next hop is a private router nyx does not manage, so the network continues upstream (this is a branch)",
	topology.NextHopUnknown:        "next hop not observable",
}

// describeFingerprintEdge answers "am I seeing the whole network, or a
// branch?" without printing the next-hop address.
func describeFingerprintEdge(edge topology.FingerprintEdge) string {
	if edge.Provider == "" {
		return "Edge: unknown; no provider route observed"
	}
	return fmt.Sprintf("Edge: %s; %s", edge.Provider, fingerprintNextHop[edge.NextHop])
}

func init() {
	addTopologyFingerprintFlags(topologyCmd)
	topologyCmd.Flags().StringVar(&topoOmadaHost, "omada-host", "", "Omada controller IP or hostname (omit to skip Omada)")
	topologyCmd.Flags().StringVar(&topoOmadaClientID, "omada-client-id", "", "Omada Open API client ID")
	topologyCmd.Flags().StringVar(&topoOmadaClientSecret, "omada-client-secret", "", "Omada Open API client secret")
	topologyCmd.Flags().StringVar(&topoOmadaSite, "omada-site", "", "Omada site name (defaults to first site)")
	topologyCmd.Flags().StringVar(&topoOpnsenseHost, "opnsense-host", "", "OPNsense firewall IP or hostname (omit to skip OPNsense)")
	topologyCmd.Flags().StringVar(&topoOpnsenseAPIKey, "opnsense-api-key", "", "OPNsense API key")
	topologyCmd.Flags().StringVar(&topoOpnsenseAPISecret, "opnsense-api-secret", "", "OPNsense API secret")
	topologyCmd.Flags().BoolVar(&topoSkipTLSVerify, "skip-tls-verify", false, "Skip TLS certificate verification for controllers (like curl -k)")
	topologyCmd.Flags().StringVar(&topoCACertPath, "ca-cert", "", "Path to custom CA certificate PEM file for controllers")
}
