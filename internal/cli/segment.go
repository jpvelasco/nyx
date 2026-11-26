package cli

import (
	"context"

	"github.com/jpvelasco/nyx/internal/service"
	"github.com/spf13/cobra"
)

func buildSegmentCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "segment", Short: "Plan and provision a routed access segment"}
	for _, name := range []string{"plan", "apply"} {
		var r service.SegmentRequest
		dry := true
		sub := &cobra.Command{Use: name, Short: name + " a segment across Omada and OPNsense", Args: cobra.NoArgs, RunE: func(c *cobra.Command, _ []string) error {
			if err := r.Validate(); err != nil {
				return err
			}
			om, err := resolvePlaybookOmadaOpts()
			if err != nil {
				return err
			}
			fw, err := resolvePlaybookOpnsenseOpts()
			if err != nil {
				return err
			}
			dur, err := extraTimeout()
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(c.Context(), dur)
			defer cancel()
			svc := service.SegmentService{Topology: service.NewTopologyService()}
			report, err := svc.Reconcile(ctx, service.PlaybookOptions{Omada: om, Opnsense: fw}, r, dry)
			if err != nil {
				return err
			}
			if err = printJSON(report); err != nil {
				return err
			}
			return report.Attention()
		}}
		f := sub.Flags()
		f.StringVar(&r.Role, "role", "", "Network role")
		f.StringVar(&r.Parent, "parent", "", "Firewall parent interface")
		f.IntVar(&r.Tag, "tag", 0, "VLAN tag")
		f.StringVar(&r.Gateway, "gateway", "", "Static IPv4 interface with prefix")
		f.StringVar(&r.Management, "management-prefix", "", "Protected management subnet")
		f.StringVar(&r.Resolver, "resolver", "", "Permitted DNS resolver")
		f.StringVar(&r.Start, "pool-start", "", "First DHCP address")
		f.StringVar(&r.End, "pool-end", "", "Last DHCP address")
		f.StringVar(&r.SSID, "ssid", "", "Existing secured SSID to verify")
		if name == "apply" {
			f.BoolVar(&dry, "dry-run", true, "Preview all steps")
		}
		cmd.AddCommand(sub)
	}
	bindPlaybookFlags(cmd.PersistentFlags())
	return cmd
}

func init() { rootCmd.AddCommand(buildSegmentCmd()) }
