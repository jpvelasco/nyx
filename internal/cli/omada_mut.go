package cli

import (
	"context"
	"fmt"
	"os"

	providers "github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/spf13/cobra"
)

func buildOmadaPlanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plan",
		Short: "Preview ACL diffs between the controller and a proposed spec (read-only)",
		RunE: func(_ *cobra.Command, _ []string) error {
			if specFile == "" {
				return fmt.Errorf("--spec is required: path to the proposed intent YAML")
			}
			// #nosec G304 — path from CLI flag
			raw, err := os.ReadFile(specFile) // nosemgrep: go_filesystem_rule-fileread
			if err != nil {
				return fmt.Errorf("reading spec: %w", err)
			}
			return withProviderSession("omada", func(ctx context.Context, opts providers.ImportOptions) error {
				plan, err := service.NewOmadaService().Plan(ctx, toOmadaOptions(opts), string(raw))
				if err != nil {
					return err
				}
				if jsonOutput {
					return printJSON(plan)
				}
				fmt.Printf("Plan: site=%s proposed=%s add=%d remove=%d change=%d unchanged=%d\n",
					plan.Site, plan.ProposedSite, len(plan.ToAdd), len(plan.ToRemove), len(plan.ToChange), len(plan.Unchanged))
				return nil
			})
		},
	}
	cmd.Flags().StringVar(&providerSite, "site", "", "Site name (defaults to first site)")
	addProviderFlags(cmd, "omada")
	return cmd
}

func buildOmadaApplyACLCmd() *cobra.Command {
	var (
		from, to, action, scope, protocols, policyName string
		dryRun, postAudit                              bool
	)
	cmd := &cobra.Command{
		Use:   "apply-acl",
		Short: "Apply one ACL change (N-to-M). Dry-run by default",
		RunE: func(_ *cobra.Command, _ []string) error {
			fromList := splitCSV(from)
			toList := splitCSV(to)
			if len(fromList) == 0 {
				return fmt.Errorf("--from is required")
			}
			if len(toList) == 0 {
				return fmt.Errorf("--to is required")
			}
			if action == "" {
				return fmt.Errorf("--action is required")
			}
			protos, err := parseProtocolList(protocols)
			if err != nil {
				return err
			}
			req := service.OmadaACLApplyRequest{
				PolicyName: policyName,
				From:       fromList,
				To:         toList,
				Action:     action,
				Scope:      scope,
				Protocols:  protos,
				DryRun:     dryRun,
				PostAudit:  postAudit,
			}
			return withProviderSession("omada", func(ctx context.Context, opts providers.ImportOptions) error {
				res, err := service.NewOmadaService().ApplyACL(ctx, toOmadaOptions(opts), req)
				if err != nil {
					return err
				}
				return printApply(res, res.Outcome, res.DryRun)
			})
		},
	}
	cmd.Flags().StringVar(&from, "from", "", "Source network names, comma-separated (required)")
	cmd.Flags().StringVar(&to, "to", "", "Destination network names, comma-separated (required)")
	cmd.Flags().StringVar(&action, "action", "", "allow or deny (required)")
	cmd.Flags().StringVar(&scope, "scope", "", "switch (default) or gateway")
	cmd.Flags().StringVar(&protocols, "protocols", "", "IP protocol numbers, comma-separated (empty = all)")
	cmd.Flags().StringVar(&policyName, "policy-name", "", "Optional policy name")
	cmd.Flags().BoolVar(&postAudit, "post-audit", true, "Run a targeted isolation audit after a real apply")
	addDryRunFlag(cmd, &dryRun)
	cmd.Flags().StringVar(&providerSite, "site", "", "Site name (defaults to first site)")
	addProviderFlags(cmd, "omada")
	return cmd
}

type omadaPortFlags struct {
	switchMAC, native, tagged, profileName string
	port                                   int
}

func (f omadaPortFlags) request() (service.OmadaPortProfileRequest, error) {
	if f.switchMAC == "" {
		return service.OmadaPortProfileRequest{}, fmt.Errorf("--switch-mac is required")
	}
	if f.port <= 0 {
		return service.OmadaPortProfileRequest{}, fmt.Errorf("--port is required (1-based port number)")
	}
	if f.native == "" {
		return service.OmadaPortProfileRequest{}, fmt.Errorf("--native is required")
	}
	return service.OmadaPortProfileRequest{
		SwitchMAC:   f.switchMAC,
		Port:        f.port,
		Native:      f.native,
		Tagged:      splitCSV(f.tagged),
		ProfileName: f.profileName,
	}, nil
}

func bindOmadaPortFlags(cmd *cobra.Command, f *omadaPortFlags) {
	cmd.Flags().StringVar(&f.switchMAC, "switch-mac", "", "Switch MAC (required)")
	cmd.Flags().IntVar(&f.port, "port", 0, "1-based port number (required)")
	cmd.Flags().StringVar(&f.native, "native", "", "Native (untagged) network name (required)")
	cmd.Flags().StringVar(&f.tagged, "tagged", "", "Tagged network names, comma-separated")
	cmd.Flags().StringVar(&f.profileName, "profile-name", "", "Optional LAN profile name (derived when empty)")
	cmd.Flags().StringVar(&providerSite, "site", "", "Site name (defaults to first site)")
	addProviderFlags(cmd, "omada")
}

func buildOmadaPlanPortCmd() *cobra.Command {
	var f omadaPortFlags
	cmd := &cobra.Command{
		Use:   "plan-port",
		Short: "Preview binding a switch port to a VLAN membership (read-only)",
		RunE: func(_ *cobra.Command, _ []string) error {
			req, err := f.request()
			if err != nil {
				return err
			}
			return withProviderSession("omada", func(ctx context.Context, opts providers.ImportOptions) error {
				plan, err := service.NewOmadaService().PlanPort(ctx, toOmadaOptions(opts), req)
				if err != nil {
					return err
				}
				return printPlan(plan, plan.Outcome)
			})
		},
	}
	bindOmadaPortFlags(cmd, &f)
	return cmd
}

func buildOmadaApplyPortProfileCmd() *cobra.Command {
	var f omadaPortFlags
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "apply-port-profile",
		Short: "Bind a switch port to a matching LAN profile. Dry-run by default",
		RunE: func(_ *cobra.Command, _ []string) error {
			req, err := f.request()
			if err != nil {
				return err
			}
			return withProviderSession("omada", func(ctx context.Context, opts providers.ImportOptions) error {
				res, err := service.NewOmadaService().ApplyPortProfile(ctx, toOmadaOptions(opts), req, dryRun)
				if err != nil {
					return err
				}
				return printApply(res, res.Outcome, res.DryRun)
			})
		},
	}
	bindOmadaPortFlags(cmd, &f)
	addDryRunFlag(cmd, &dryRun)
	return cmd
}

type omadaLANFlags struct {
	name, gatewaySubnet, dhcpStart, dhcpEnd, dhcpDNS string
	vlan, leaseTime                                  int
	isolated, dhcpEnabled, dhcpL2Relay, dhcpGuard    bool
	igmpSnoop, mldSnoop, delete                      bool
}

func (f omadaLANFlags) request() (service.OmadaLANRequest, error) {
	if f.name == "" {
		return service.OmadaLANRequest{}, fmt.Errorf("--name is required")
	}
	return service.OmadaLANRequest{
		Name:          f.name,
		VLAN:          f.vlan,
		GatewaySubnet: f.gatewaySubnet,
		Isolated:      f.isolated,
		DHCPEnabled:   f.dhcpEnabled,
		DHCPStart:     f.dhcpStart,
		DHCPEnd:       f.dhcpEnd,
		LeaseTime:     f.leaseTime,
		DHCPDNS:       f.dhcpDNS,
		DHCPL2Relay:   f.dhcpL2Relay,
		DHCPGuard:     f.dhcpGuard,
		IGMPSnoop:     f.igmpSnoop,
		MLDSnoop:      f.mldSnoop,
		Delete:        f.delete,
	}, nil
}

func bindOmadaLANFlags(cmd *cobra.Command, f *omadaLANFlags) {
	cmd.Flags().StringVar(&f.name, "name", "", "LAN network name (required)")
	cmd.Flags().IntVar(&f.vlan, "vlan", 0, "VLAN ID")
	cmd.Flags().StringVar(&f.gatewaySubnet, "gateway-subnet", "", "Gateway CIDR (e.g. 10.0.10.1/24)")
	cmd.Flags().BoolVar(&f.isolated, "isolated", false, "Isolate this LAN from others")
	cmd.Flags().BoolVar(&f.dhcpEnabled, "dhcp-enabled", false, "Enable DHCP on this LAN")
	cmd.Flags().StringVar(&f.dhcpStart, "dhcp-start", "", "DHCP pool start address")
	cmd.Flags().StringVar(&f.dhcpEnd, "dhcp-end", "", "DHCP pool end address")
	cmd.Flags().IntVar(&f.leaseTime, "lease-time", 0, "DHCP lease time (seconds)")
	cmd.Flags().StringVar(&f.dhcpDNS, "dhcp-dns", "", "DHCP DNS server")
	cmd.Flags().BoolVar(&f.dhcpL2Relay, "dhcp-l2-relay", false, "Enable DHCP L2 relay")
	cmd.Flags().BoolVar(&f.dhcpGuard, "dhcp-guard", false, "Enable DHCP guard")
	cmd.Flags().BoolVar(&f.igmpSnoop, "igmp-snoop", false, "Enable IGMP snooping")
	cmd.Flags().BoolVar(&f.mldSnoop, "mld-snoop", false, "Enable MLD snooping")
	cmd.Flags().BoolVar(&f.delete, "delete", false, "Delete the named LAN")
	cmd.Flags().StringVar(&providerSite, "site", "", "Site name (defaults to first site)")
	addProviderFlags(cmd, "omada")
}

func buildOmadaPlanLANCmd() *cobra.Command {
	var f omadaLANFlags
	cmd := &cobra.Command{
		Use:   "plan-lan",
		Short: "Preview creating, updating, or deleting a site LAN (read-only)",
		RunE: func(_ *cobra.Command, _ []string) error {
			req, err := f.request()
			if err != nil {
				return err
			}
			return withProviderSession("omada", func(ctx context.Context, opts providers.ImportOptions) error {
				plan, err := service.NewOmadaService().PlanLAN(ctx, toOmadaOptions(opts), req)
				if err != nil {
					return err
				}
				return printPlan(plan, plan.Action)
			})
		},
	}
	bindOmadaLANFlags(cmd, &f)
	return cmd
}

func buildOmadaApplyLANCmd() *cobra.Command {
	var f omadaLANFlags
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "apply-lan",
		Short: "Create, update, or delete a site LAN. Dry-run by default",
		RunE: func(_ *cobra.Command, _ []string) error {
			req, err := f.request()
			if err != nil {
				return err
			}
			return withProviderSession("omada", func(ctx context.Context, opts providers.ImportOptions) error {
				res, err := service.NewOmadaService().ApplyLAN(ctx, toOmadaOptions(opts), req, dryRun)
				if err != nil {
					return err
				}
				return printApply(res, res.Outcome, res.DryRun)
			})
		},
	}
	bindOmadaLANFlags(cmd, &f)
	addDryRunFlag(cmd, &dryRun)
	return cmd
}

type omadaSSIDFlags struct {
	name, ssid, wlanGroup, security, band string
	vlan                                  int
	enabled, delete                       bool
}

func (f omadaSSIDFlags) request() (service.OmadaSSIDRequest, error) {
	if f.name == "" && f.ssid == "" {
		return service.OmadaSSIDRequest{}, fmt.Errorf("--name or --ssid is required")
	}
	return service.OmadaSSIDRequest{
		Name:      f.name,
		SSID:      f.ssid,
		Enabled:   f.enabled,
		WLANGroup: f.wlanGroup,
		VLAN:      f.vlan,
		Security:  f.security,
		Band:      f.band,
		Delete:    f.delete,
	}, nil
}

func bindOmadaSSIDFlags(cmd *cobra.Command, f *omadaSSIDFlags) {
	cmd.Flags().StringVar(&f.name, "name", "", "SSID object name")
	cmd.Flags().StringVar(&f.ssid, "ssid", "", "Broadcast SSID")
	cmd.Flags().BoolVar(&f.enabled, "enabled", false, "Enable the SSID")
	cmd.Flags().StringVar(&f.wlanGroup, "wlan-group", "", "WLAN group name or ID")
	cmd.Flags().IntVar(&f.vlan, "vlan", 0, "VLAN ID")
	cmd.Flags().StringVar(&f.security, "security", "", "Security mode")
	cmd.Flags().StringVar(&f.band, "band", "", "Radio band")
	cmd.Flags().BoolVar(&f.delete, "delete", false, "Delete the named SSID")
	cmd.Flags().StringVar(&providerSite, "site", "", "Site name (defaults to first site)")
	addProviderFlags(cmd, "omada")
}

func buildOmadaPlanSSIDCmd() *cobra.Command {
	var f omadaSSIDFlags
	cmd := &cobra.Command{
		Use:   "plan-ssid",
		Short: "Preview creating, updating, or deleting a site SSID (read-only)",
		RunE: func(_ *cobra.Command, _ []string) error {
			req, err := f.request()
			if err != nil {
				return err
			}
			return withProviderSession("omada", func(ctx context.Context, opts providers.ImportOptions) error {
				plan, err := service.NewOmadaService().PlanSSID(ctx, toOmadaOptions(opts), req)
				if err != nil {
					return err
				}
				return printPlan(plan, plan.Action)
			})
		},
	}
	bindOmadaSSIDFlags(cmd, &f)
	return cmd
}

func buildOmadaApplySSIDCmd() *cobra.Command {
	var f omadaSSIDFlags
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "apply-ssid",
		Short: "Create, update, or delete a site SSID. Dry-run by default",
		RunE: func(_ *cobra.Command, _ []string) error {
			req, err := f.request()
			if err != nil {
				return err
			}
			return withProviderSession("omada", func(ctx context.Context, opts providers.ImportOptions) error {
				res, err := service.NewOmadaService().ApplySSID(ctx, toOmadaOptions(opts), req, dryRun)
				if err != nil {
					return err
				}
				return printApply(res, res.Outcome, res.DryRun)
			})
		},
	}
	bindOmadaSSIDFlags(cmd, &f)
	addDryRunFlag(cmd, &dryRun)
	return cmd
}
