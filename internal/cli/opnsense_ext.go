package cli

import (
	"context"
	"fmt"

	providers "github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/spf13/cobra"
)

// opnsense-specific extra subcommands (observation + plan/apply mutations)
// added on top of the capability-derived commands. They are deliberately
// NOT advertised via Capabilities() — extras stay off the capability
// parity gate (see the CLI/MCP surface split in AGENTS.md). Writes default
// to dry-run, matching the MCP tools.

func buildOpnsenseExtraCommands() []*cobra.Command {
	return []*cobra.Command{
		buildOpnsenseListCmd("list-vlans", "List configured VLAN devices", func(ctx context.Context, opts service.OpnsenseOptions) (any, error) {
			return service.NewOpnsenseService().ListVLANs(ctx, opts)
		}),
		buildOpnsenseListCmd("list-kea-subnets", "List Kea DHCPv4 subnets", func(ctx context.Context, opts service.OpnsenseOptions) (any, error) {
			return service.NewOpnsenseService().ListKeaSubnets(ctx, opts)
		}),
		buildOpnsenseListCmd("list-kea-reservations", "List Kea DHCPv4 reservations", func(ctx context.Context, opts service.OpnsenseOptions) (any, error) {
			return service.NewOpnsenseService().ListKeaReservations(ctx, opts)
		}),
		buildOpnsenseListCmd("list-wireguard-servers", "List WireGuard server instances", func(ctx context.Context, opts service.OpnsenseOptions) (any, error) {
			return service.NewOpnsenseService().ListWireGuardServers(ctx, opts)
		}),
		buildOpnsenseListCmd("list-wireguard-clients", "List WireGuard peers", func(ctx context.Context, opts service.OpnsenseOptions) (any, error) {
			return service.NewOpnsenseService().ListWireGuardClients(ctx, opts)
		}),
		buildOpnsenseListCmd("wireguard-status", "Show whether the WireGuard service is running", func(ctx context.Context, opts service.OpnsenseOptions) (any, error) {
			return service.NewOpnsenseService().GetWireGuardStatus(ctx, opts)
		}),
		buildOpnsenseListCmd("unbound-settings", "Show Unbound enabled/interfaces/overrides", func(ctx context.Context, opts service.OpnsenseOptions) (any, error) {
			return service.NewOpnsenseService().GetUnboundSettings(ctx, opts)
		}),
		buildOpnsenseListCmd("list-unbound-overrides", "List Unbound host overrides", func(ctx context.Context, opts service.OpnsenseOptions) (any, error) {
			return service.NewOpnsenseService().ListUnboundOverrides(ctx, opts)
		}),
		buildOpnsenseListCmd("unbound-status", "Show whether Unbound is running", func(ctx context.Context, opts service.OpnsenseOptions) (any, error) {
			return service.NewOpnsenseService().GetUnboundStatus(ctx, opts)
		}),
		buildOpnsensePlanNatCmd(),
		buildOpnsenseApplyNatCmd(),
		buildOpnsensePlanVLANCmd(),
		buildOpnsenseApplyVLANCmd(),
		buildOpnsensePlanFilterCmd(),
		buildOpnsenseApplyFilterCmd(),
		buildOpnsensePlanUnboundCmd(),
		buildOpnsenseApplyUnboundCmd(),
		buildOpnsensePlanDHCPCmd(),
		buildOpnsenseApplyDHCPCmd(),
	}
}

func buildOpnsenseListCmd(use, short string, fetch func(context.Context, service.OpnsenseOptions) (any, error)) *cobra.Command {
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		RunE: func(_ *cobra.Command, _ []string) error {
			return withProviderSession("opnsense", func(ctx context.Context, opts providers.ImportOptions) error {
				v, err := fetch(ctx, toOpnsenseOptions(opts))
				if err != nil {
					return err
				}
				return printJSON(v)
			})
		},
	}
	addProviderFlags(cmd, "opnsense")
	return cmd
}

type opnsenseNatFlags struct {
	operation, action, ruleUUID               string
	interfaces, protocol, source, destination string
	port, localPort, target, typ, label       string
	toggleDisable, allowDoubleNat, dryRun     bool
}

func (f opnsenseNatFlags) request() (service.OpnsenseNatApplyRequest, error) {
	if f.operation == "" {
		return service.OpnsenseNatApplyRequest{}, fmt.Errorf("--operation is required: port_forward, one_to_one, or source_nat")
	}
	action := f.action
	if action == "" {
		action = "create"
	}
	if action != "create" && f.ruleUUID == "" {
		return service.OpnsenseNatApplyRequest{}, fmt.Errorf("--rule-uuid is required for action %q", action)
	}
	return service.OpnsenseNatApplyRequest{
		Operation:      f.operation,
		Action:         f.action,
		RuleUUID:       f.ruleUUID,
		ToggleDisable:  f.toggleDisable,
		AllowDoubleNat: f.allowDoubleNat,
		DryRun:         f.dryRun,
		Spec: service.OpnsenseNatRuleSpec{
			Interfaces:  splitCSV(f.interfaces),
			Protocol:    f.protocol,
			Source:      f.source,
			Destination: f.destination,
			Port:        f.port,
			LocalPort:   f.localPort,
			Target:      f.target,
			Type:        f.typ,
			Label:       f.label,
		},
	}, nil
}

func bindOpnsenseNatFlags(cmd *cobra.Command, f *opnsenseNatFlags) {
	cmd.Flags().StringVar(&f.operation, "operation", "", "port_forward, one_to_one, or source_nat (required)")
	cmd.Flags().StringVar(&f.action, "action", "", "create (default), update, delete, or toggle")
	cmd.Flags().StringVar(&f.ruleUUID, "rule-uuid", "", "Existing rule UUID (required for update/delete/toggle)")
	cmd.Flags().StringVar(&f.interfaces, "interfaces", "", "Interfaces, comma-separated")
	cmd.Flags().StringVar(&f.protocol, "protocol", "", "Protocol (tcp, udp, …)")
	cmd.Flags().StringVar(&f.source, "source", "", "Source address or alias")
	cmd.Flags().StringVar(&f.destination, "destination", "", "Destination address or alias")
	cmd.Flags().StringVar(&f.port, "port", "", "External / match port")
	cmd.Flags().StringVar(&f.localPort, "local-port", "", "Local / translated port")
	cmd.Flags().StringVar(&f.target, "target", "", "Translation target")
	cmd.Flags().StringVar(&f.typ, "type", "", "Rule type (source NAT)")
	cmd.Flags().StringVar(&f.label, "label", "", "Rule label")
	cmd.Flags().BoolVar(&f.toggleDisable, "toggle-disable", false, "Disable the rule when action=toggle")
	cmd.Flags().BoolVar(&f.allowDoubleNat, "allow-double-nat", false, "Bypass the double-NAT guard")
	addProviderFlags(cmd, "opnsense")
}

func buildOpnsensePlanNatCmd() *cobra.Command {
	var f opnsenseNatFlags
	f.dryRun = true
	cmd := &cobra.Command{
		Use:   "plan-nat",
		Short: "Preview a NAT mutation without writing (read-only)",
		RunE: func(_ *cobra.Command, _ []string) error {
			req, err := f.request()
			if err != nil {
				return err
			}
			return withProviderSession("opnsense", func(ctx context.Context, opts providers.ImportOptions) error {
				plan, err := service.NewOpnsenseService().PlanNat(ctx, toOpnsenseOptions(opts), req)
				if err != nil {
					return err
				}
				return printPlan(plan, plan.Outcome)
			})
		},
	}
	bindOpnsenseNatFlags(cmd, &f)
	return cmd
}

func buildOpnsenseApplyNatCmd() *cobra.Command {
	var f opnsenseNatFlags
	cmd := &cobra.Command{
		Use:   "apply-nat",
		Short: "Apply a NAT mutation. Dry-run by default",
		RunE: func(_ *cobra.Command, _ []string) error {
			req, err := f.request()
			if err != nil {
				return err
			}
			return withProviderSession("opnsense", func(ctx context.Context, opts providers.ImportOptions) error {
				res, err := service.NewOpnsenseService().ApplyNat(ctx, toOpnsenseOptions(opts), req)
				if err != nil {
					return err
				}
				return printApply(res, res.Outcome, res.DryRun)
			})
		},
	}
	bindOpnsenseNatFlags(cmd, &f)
	addDryRunFlag(cmd, &f.dryRun)
	return cmd
}

type opnsenseVLANFlags struct {
	kind, parent, description, uuid, members string
	tag                                      int
	delete                                   bool
}

func (f opnsenseVLANFlags) request() service.OpnsenseVLANRequest {
	return service.OpnsenseVLANRequest{
		Kind:        f.kind,
		Parent:      f.parent,
		Tag:         f.tag,
		Description: f.description,
		UUID:        f.uuid,
		Members:     splitCSV(f.members),
		Delete:      f.delete,
	}
}

func bindOpnsenseVLANFlags(cmd *cobra.Command, f *opnsenseVLANFlags) {
	cmd.Flags().StringVar(&f.kind, "kind", "", "vlan (default) or bridge")
	cmd.Flags().StringVar(&f.parent, "parent", "", "Parent interface (required for VLAN create/update)")
	cmd.Flags().IntVar(&f.tag, "tag", 0, "VLAN tag (required for VLAN create/update)")
	cmd.Flags().StringVar(&f.description, "description", "", "Description")
	cmd.Flags().StringVar(&f.uuid, "uuid", "", "Existing UUID (required for bridge updates and VLAN delete-by-id)")
	cmd.Flags().StringVar(&f.members, "members", "", "Bridge members, comma-separated")
	cmd.Flags().BoolVar(&f.delete, "delete", false, "Delete the VLAN")
	addProviderFlags(cmd, "opnsense")
}

func buildOpnsensePlanVLANCmd() *cobra.Command {
	var f opnsenseVLANFlags
	cmd := &cobra.Command{
		Use:   "plan-vlan",
		Short: "Preview a VLAN or bridge-member change (read-only)",
		RunE: func(_ *cobra.Command, _ []string) error {
			return withProviderSession("opnsense", func(ctx context.Context, opts providers.ImportOptions) error {
				plan, err := service.NewOpnsenseService().PlanVLAN(ctx, toOpnsenseOptions(opts), f.request())
				if err != nil {
					return err
				}
				return printPlan(plan, plan.Action)
			})
		},
	}
	bindOpnsenseVLANFlags(cmd, &f)
	return cmd
}

func buildOpnsenseApplyVLANCmd() *cobra.Command {
	var f opnsenseVLANFlags
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "apply-vlan",
		Short: "Create, update, or delete a VLAN (or update bridge members). Dry-run by default",
		RunE: func(_ *cobra.Command, _ []string) error {
			return withProviderSession("opnsense", func(ctx context.Context, opts providers.ImportOptions) error {
				res, err := service.NewOpnsenseService().ApplyVLAN(ctx, toOpnsenseOptions(opts), f.request(), dryRun)
				if err != nil {
					return err
				}
				return printApply(res, res.Outcome, res.DryRun)
			})
		},
	}
	bindOpnsenseVLANFlags(cmd, &f)
	addDryRunFlag(cmd, &dryRun)
	return cmd
}

type opnsenseFilterFlags struct {
	kind, uuid, name, action, iface, protocol string
	source, destination, addresses, aliasType string
	description                               string
	enabled, delete                           bool
}

func (f opnsenseFilterFlags) request() service.OpnsenseFilterRequest {
	return service.OpnsenseFilterRequest{
		Kind:        f.kind,
		UUID:        f.uuid,
		Name:        f.name,
		Action:      f.action,
		Interface:   f.iface,
		Protocol:    f.protocol,
		Source:      f.source,
		Destination: f.destination,
		Addresses:   splitCSV(f.addresses),
		AliasType:   f.aliasType,
		Description: f.description,
		Enabled:     f.enabled,
		Delete:      f.delete,
	}
}

func bindOpnsenseFilterFlags(cmd *cobra.Command, f *opnsenseFilterFlags) {
	cmd.Flags().StringVar(&f.kind, "kind", "", "filter (default) or alias")
	cmd.Flags().StringVar(&f.uuid, "uuid", "", "Existing UUID")
	cmd.Flags().StringVar(&f.name, "name", "", "Alias name")
	cmd.Flags().StringVar(&f.action, "action", "", "Filter action (pass, block, reject)")
	cmd.Flags().StringVar(&f.iface, "interface", "", "Filter interface")
	cmd.Flags().StringVar(&f.protocol, "protocol", "", "Protocol")
	cmd.Flags().StringVar(&f.source, "source", "", "Source address or alias")
	cmd.Flags().StringVar(&f.destination, "destination", "", "Destination address or alias")
	cmd.Flags().StringVar(&f.addresses, "addresses", "", "Alias addresses, comma-separated")
	cmd.Flags().StringVar(&f.aliasType, "alias-type", "", "Alias type")
	cmd.Flags().StringVar(&f.description, "description", "", "Description")
	cmd.Flags().BoolVar(&f.enabled, "enabled", true, "Enable the filter rule or alias")
	cmd.Flags().BoolVar(&f.delete, "delete", false, "Delete the rule or alias")
	addProviderFlags(cmd, "opnsense")
}

func buildOpnsensePlanFilterCmd() *cobra.Command {
	var f opnsenseFilterFlags
	f.enabled = true
	cmd := &cobra.Command{
		Use:   "plan-filter",
		Short: "Preview a filter-rule or alias change (read-only)",
		RunE: func(_ *cobra.Command, _ []string) error {
			return withProviderSession("opnsense", func(ctx context.Context, opts providers.ImportOptions) error {
				plan, err := service.NewOpnsenseService().PlanFilter(ctx, toOpnsenseOptions(opts), f.request())
				if err != nil {
					return err
				}
				return printPlan(plan, plan.Action)
			})
		},
	}
	bindOpnsenseFilterFlags(cmd, &f)
	return cmd
}

func buildOpnsenseApplyFilterCmd() *cobra.Command {
	var f opnsenseFilterFlags
	var dryRun bool
	f.enabled = true
	cmd := &cobra.Command{
		Use:   "apply-filter",
		Short: "Create, update, or delete a filter rule or alias. Dry-run by default",
		RunE: func(_ *cobra.Command, _ []string) error {
			return withProviderSession("opnsense", func(ctx context.Context, opts providers.ImportOptions) error {
				res, err := service.NewOpnsenseService().ApplyFilter(ctx, toOpnsenseOptions(opts), f.request(), dryRun)
				if err != nil {
					return err
				}
				return printApply(res, res.Outcome, res.DryRun)
			})
		},
	}
	bindOpnsenseFilterFlags(cmd, &f)
	addDryRunFlag(cmd, &dryRun)
	return cmd
}

type opnsenseUnboundFlags struct {
	hostname, domain, ip, uuid, description string
	delete                                  bool
}

func (f opnsenseUnboundFlags) request() service.OpnsenseUnboundOverrideRequest {
	return service.OpnsenseUnboundOverrideRequest{
		Hostname:    f.hostname,
		Domain:      f.domain,
		IP:          f.ip,
		UUID:        f.uuid,
		Description: f.description,
		Delete:      f.delete,
	}
}

func bindOpnsenseUnboundFlags(cmd *cobra.Command, f *opnsenseUnboundFlags) {
	cmd.Flags().StringVar(&f.hostname, "hostname", "", "Override hostname")
	cmd.Flags().StringVar(&f.domain, "domain", "", "Override domain")
	cmd.Flags().StringVar(&f.ip, "ip", "", "Override IP")
	cmd.Flags().StringVar(&f.uuid, "uuid", "", "Existing override UUID")
	cmd.Flags().StringVar(&f.description, "description", "", "Description")
	cmd.Flags().BoolVar(&f.delete, "delete", false, "Delete the override")
	addProviderFlags(cmd, "opnsense")
}

func buildOpnsensePlanUnboundCmd() *cobra.Command {
	var f opnsenseUnboundFlags
	cmd := &cobra.Command{
		Use:   "plan-unbound-override",
		Short: "Preview an Unbound host-override change (read-only)",
		RunE: func(_ *cobra.Command, _ []string) error {
			return withProviderSession("opnsense", func(ctx context.Context, opts providers.ImportOptions) error {
				plan, err := service.NewOpnsenseService().PlanUnboundOverride(ctx, toOpnsenseOptions(opts), f.request())
				if err != nil {
					return err
				}
				return printPlan(plan, plan.Action)
			})
		},
	}
	bindOpnsenseUnboundFlags(cmd, &f)
	return cmd
}

func buildOpnsenseApplyUnboundCmd() *cobra.Command {
	var f opnsenseUnboundFlags
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "apply-unbound-override",
		Short: "Create, update, or delete an Unbound host override. Dry-run by default",
		RunE: func(_ *cobra.Command, _ []string) error {
			return withProviderSession("opnsense", func(ctx context.Context, opts providers.ImportOptions) error {
				res, err := service.NewOpnsenseService().ApplyUnboundOverride(ctx, toOpnsenseOptions(opts), f.request(), dryRun)
				if err != nil {
					return err
				}
				return printApply(res, res.Outcome, res.DryRun)
			})
		},
	}
	bindOpnsenseUnboundFlags(cmd, &f)
	addDryRunFlag(cmd, &dryRun)
	return cmd
}

type opnsenseDHCPFlags struct {
	backend, kind, iface, start, end, ip, mac, hostname, uuid string
	delete                                                    bool
}

func (f opnsenseDHCPFlags) request() service.OpnsenseDHCPRequest {
	return service.OpnsenseDHCPRequest{
		Backend:   f.backend,
		Kind:      f.kind,
		Interface: f.iface,
		Start:     f.start,
		End:       f.end,
		IP:        f.ip,
		MAC:       f.mac,
		Hostname:  f.hostname,
		UUID:      f.uuid,
		Delete:    f.delete,
	}
}

func bindOpnsenseDHCPFlags(cmd *cobra.Command, f *opnsenseDHCPFlags) {
	cmd.Flags().StringVar(&f.backend, "backend", "", "auto (default), dnsmasq, or kea")
	cmd.Flags().StringVar(&f.kind, "kind", "", "range (default), host, or reservation")
	cmd.Flags().StringVar(&f.iface, "interface", "", "Dnsmasq range interface")
	cmd.Flags().StringVar(&f.start, "start", "", "Range start or Kea subnet CIDR")
	cmd.Flags().StringVar(&f.end, "end", "", "Range end")
	cmd.Flags().StringVar(&f.ip, "ip", "", "Static host / reservation IP")
	cmd.Flags().StringVar(&f.mac, "mac", "", "Reservation MAC")
	cmd.Flags().StringVar(&f.hostname, "hostname", "", "Static host / reservation hostname")
	cmd.Flags().StringVar(&f.uuid, "uuid", "", "Existing item UUID")
	cmd.Flags().BoolVar(&f.delete, "delete", false, "Delete the item")
	addProviderFlags(cmd, "opnsense")
}

func buildOpnsensePlanDHCPCmd() *cobra.Command {
	var f opnsenseDHCPFlags
	cmd := &cobra.Command{
		Use:   "plan-dhcp",
		Short: "Preview a DHCP range, host, or reservation change (read-only)",
		RunE: func(_ *cobra.Command, _ []string) error {
			return withProviderSession("opnsense", func(ctx context.Context, opts providers.ImportOptions) error {
				plan, err := service.NewOpnsenseService().PlanDHCP(ctx, toOpnsenseOptions(opts), f.request())
				if err != nil {
					return err
				}
				return printPlan(plan, plan.Action)
			})
		},
	}
	bindOpnsenseDHCPFlags(cmd, &f)
	return cmd
}

func buildOpnsenseApplyDHCPCmd() *cobra.Command {
	var f opnsenseDHCPFlags
	var dryRun bool
	cmd := &cobra.Command{
		Use:   "apply-dhcp",
		Short: "Create, update, or delete a DHCP range, host, or reservation. Dry-run by default",
		RunE: func(_ *cobra.Command, _ []string) error {
			return withProviderSession("opnsense", func(ctx context.Context, opts providers.ImportOptions) error {
				res, err := service.NewOpnsenseService().ApplyDHCP(ctx, toOpnsenseOptions(opts), f.request(), dryRun)
				if err != nil {
					return err
				}
				return printApply(res, res.Outcome, res.DryRun)
			})
		},
	}
	bindOpnsenseDHCPFlags(cmd, &f)
	addDryRunFlag(cmd, &dryRun)
	return cmd
}
