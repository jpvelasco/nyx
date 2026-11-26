package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jpvelasco/nyx/internal/credentials"
	"github.com/jpvelasco/nyx/internal/credentials/credmanager"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/jpvelasco/nyx/internal/storepath"
	"github.com/jpvelasco/nyx/internal/topology"
	"github.com/spf13/cobra"
)

var (
	topoOmadaProfile      string
	topoOpnsenseProfile   string
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

		topoOpts := service.TopologyOptions{Omada: omadaOpts, Opnsense: opnsOpts}
		applyTopologyFingerprintFlags(cmd, &topoOpts)
		rep, err := service.NewTopologyService().Report(ctx, topoOpts)
		if err != nil {
			return err
		}
		if draftPath, _ := cmd.Flags().GetString("draft-spec"); draftPath != "" {
			force, _ := cmd.Flags().GetBool("force")
			if err := writeDraftSpec(draftPath, renderDraftSpec(rep.Fingerprint, localVantageCIDRs()), force); err != nil {
				return err
			}
			fmt.Fprintln(cmd.ErrOrStderr(), draftSpecNotice(draftPath))
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

func resolveOmadaTopologyOpts() (*service.OmadaOptions, error) {
	return composedOmadaOptions(topoOmadaProfile, credentials.Entry{"host": topoOmadaHost, "site": topoOmadaSite, "client_id": topoOmadaClientID, "client_secret": topoOmadaClientSecret}, topoSkipTLSVerify, topoCACertPath)
}
func resolveOpnsenseTopologyOpts() (*service.OpnsenseOptions, error) {
	return composedOpnsenseOptions(topoOpnsenseProfile, credentials.Entry{"host": topoOpnsenseHost, "api_key": topoOpnsenseAPIKey, "api_secret": topoOpnsenseAPISecret}, topoSkipTLSVerify, topoCACertPath)
}

func composedFields(provider, profile string, fields credentials.Entry) (credentials.Entry, error) {
	c := credentials.Connection{Provider: provider, Profile: profile}
	v := credentials.Resolve(c, fields, os.Getenv, storepath.StoreFile(), true)
	err := c.Require(v)
	if profile != "" {
		return v, err
	}
	if v["host"] == "" {
		return nil, nil
	}
	if err == nil {
		return v, nil
	}
	if provider == "omada" {
		return nil, errors.New("omada credentials incomplete: set --omada-client-id/--omada-client-secret, OMADA_CLIENT_ID / OMADA_CLIENT_SECRET" + credmanager.Hint(v["host"]) + ", or run `nyx credentials set omada`")
	}
	return nil, errors.New("opnsense credentials incomplete: set --opnsense-api-key/--opnsense-api-secret, OPNSENSE_API_KEY / OPNSENSE_API_SECRET" + credmanager.HintOpnsense(v["host"]) + ", or run `nyx credentials set opnsense`")
}

func composedOmadaOptions(profile string, fields credentials.Entry, skipTLS bool, caPath string) (*service.OmadaOptions, error) {
	v, err := composedFields("omada", profile, fields)
	if err != nil || v == nil {
		return nil, err
	}
	return &service.OmadaOptions{Host: v["host"], Site: v["site"], ClientID: v["client_id"], ClientSecret: v["client_secret"], SkipTLSVerify: skipTLS, CACertPath: caPath}, nil
}

func composedOpnsenseOptions(profile string, fields credentials.Entry, skipTLS bool, caPath string) (*service.OpnsenseOptions, error) {
	v, err := composedFields("opnsense", profile, fields)
	if err != nil || v == nil {
		return nil, err
	}
	return &service.OpnsenseOptions{Host: v["host"], APIKey: v["api_key"], APISecret: v["api_secret"], SkipTLSVerify: skipTLS, CACertPath: caPath}, nil
}

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
	if fingerprint.Matrix != nil {
		printEnforcementMatrix(w, fingerprint.Matrix)
	}
	for _, warning := range fingerprint.Warnings {
		fmt.Fprintf(w, "  Warning: %s\n", warning)
	}
	fmt.Fprintln(w)
}

// printEnforcementMatrix renders the segment-pair matrix as a grid of
// allow/deny counts summed across providers ("none" = no pair-specific
// rule), the per-provider wildcard and unresolved totals, and the uncovered
// pairs as omada_plan candidates.
func printEnforcementMatrix(w io.Writer, m *topology.EnforcementMatrix) {
	if len(m.Pairs) == 0 {
		fmt.Fprintln(w, "  Enforcement matrix: fewer than two segments observed")
		return
	}
	cells := map[[2]int]string{}
	var vlans []int
	for _, p := range m.Pairs {
		vlans = append(vlans, p.From)
		cells[[2]int{p.From, p.To}] = matrixCell(p)
	}
	slices.Sort(vlans)
	vlans = slices.Compact(vlans)

	fmt.Fprintln(w, "  Enforcement matrix (rules naming each pair, allow/deny)")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	header := []string{"    from\\to"}
	for _, v := range vlans {
		header = append(header, strconv.Itoa(v))
	}
	fmt.Fprintln(tw, strings.Join(header, "\t"))
	for _, from := range vlans {
		row := []string{"    " + strconv.Itoa(from)}
		for _, to := range vlans {
			cell := "-"
			if from != to {
				cell = cells[[2]int{from, to}]
			}
			row = append(row, cell)
		}
		fmt.Fprintln(tw, strings.Join(row, "\t"))
	}
	_ = tw.Flush()

	wildcard := make([]string, 0, len(m.Providers))
	unresolved := make([]string, 0, len(m.Providers))
	for _, p := range m.Providers {
		wildcard = append(wildcard, fmt.Sprintf("%s %d", p.Provider, p.Wildcard))
		unresolved = append(unresolved, fmt.Sprintf("%s %d", p.Provider, p.Unresolved))
	}
	if len(m.Providers) > 0 {
		fmt.Fprintf(w, "  Wildcard rules: %s\n", strings.Join(wildcard, ", "))
		fmt.Fprintf(w, "  Unresolved rules: %s\n", strings.Join(unresolved, ", "))
	}
	uncovered := make([]string, 0, len(m.Pairs))
	for _, pair := range m.Uncovered() {
		uncovered = append(uncovered, fmt.Sprintf("%d->%d", pair[0], pair[1]))
	}
	if len(uncovered) == 0 {
		fmt.Fprintln(w, "  Every segment pair has a pair-specific rule")
		return
	}
	fmt.Fprintf(w, "  No pair-specific rule (omada_plan candidates): %s\n", strings.Join(uncovered, ", "))
}

func matrixCell(p topology.MatrixPair) string {
	if !p.PairSpecific {
		return "none"
	}
	allow, deny := 0, 0
	for _, r := range p.Rules {
		allow += r.Allow
		deny += r.Deny
	}
	return fmt.Sprintf("%d/%d", allow, deny)
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
	cmd.Flags().Bool("matrix", false, "With the fingerprint, also show the segment-pair enforcement matrix (implies --fingerprint)")
	cmd.Flags().String("draft-spec", "", "Write a draft intent spec built from the fingerprint to this file (private: implies --detail and --matrix)")
	cmd.Flags().Bool("force", false, "With --draft-spec, replace an existing file")
}

// applyTopologyFingerprintFlags copies the fingerprint flags into opts;
// --detail and --matrix each imply --fingerprint, and --draft-spec implies
// both, since the draft is built from their output.
func applyTopologyFingerprintFlags(cmd *cobra.Command, opts *service.TopologyOptions) {
	opts.Fingerprint, _ = cmd.Flags().GetBool("fingerprint")
	opts.Detail, _ = cmd.Flags().GetBool("detail")
	opts.Matrix, _ = cmd.Flags().GetBool("matrix")
	if draft, _ := cmd.Flags().GetString("draft-spec"); draft != "" {
		opts.Detail, opts.Matrix = true, true
	}
	opts.Fingerprint = opts.Fingerprint || opts.Detail || opts.Matrix
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
	topologyCmd.AddCommand(newNetworkMapCmd(), newClientLocationCmd(), newSwitchPortsCmd())
	addTopologyFingerprintFlags(topologyCmd)
	topologyCmd.Flags().StringVar(&topoOmadaProfile, "omada-profile", "", "Named Omada credential profile")
	topologyCmd.Flags().StringVar(&topoOpnsenseProfile, "opnsense-profile", "", "Named OPNsense credential profile")
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
