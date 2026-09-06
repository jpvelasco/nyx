package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/jpvelasco/nyx/internal/audit"
	"github.com/jpvelasco/nyx/internal/backends/nmap"
	"github.com/jpvelasco/nyx/internal/backends/system"
	"github.com/jpvelasco/nyx/internal/intent"
	"github.com/jpvelasco/nyx/internal/models"
	"github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/service"
)

// toolHandler invokes one registered MCP tool. Handlers return the response
// text and whether it represents a tool-level error.
type toolHandler func(*Server, context.Context, map[string]interface{}) toolDispatchResult

// toolHandlers routes tool names to their implementations. Adding a tool
// means writing one method and adding one entry here.
var toolHandlers = map[string]toolHandler{
	"discover_subnet":                  (*Server).toolDiscoverSubnet,
	"check_routes":                     (*Server).toolCheckRoutes,
	"check_vpn":                        (*Server).toolCheckVPN,
	"verify_isolation":                 (*Server).toolVerifyIsolation,
	"run_audit":                        (*Server).toolRunAudit,
	"load_spec":                        (*Server).toolLoadSpec,
	"get_interfaces":                   (*Server).toolGetInterfaces,
	"ping_target":                      (*Server).toolPingTarget,
	"run_doctor":                       (*Server).toolRunDoctor,
	"provider_list":                    (*Server).toolProviderList,
	"omada_get_info":                   (*Server).toolOmadaGetInfo,
	"omada_list_networks":              (*Server).toolOmadaListNetworks,
	"omada_list_acls":                  (*Server).toolOmadaListACLs,
	"omada_list_clients":               (*Server).toolOmadaListClients,
	"omada_inventory":                  (*Server).toolOmadaInventory,
	"omada_import":                     (*Server).toolOmadaImport,
	"omada_plan":                       (*Server).toolOmadaPlan,
	"omada_apply_acl":                  (*Server).toolOmadaApplyACL,
	"omada_list_port_forwardings":      (*Server).toolOmadaListPortForwardings,
	"omada_list_one_to_one_nat":        (*Server).toolOmadaListOneToOneNAT,
	"omada_get_nat_settings":           (*Server).toolOmadaGetNatSettings,
	"omada_nat_facts":                  (*Server).toolOmadaNatFacts,
	"omada_get_uplink_info":            (*Server).toolOmadaGetUplinkInfo,
	"omada_list_switch_ports":          (*Server).toolOmadaListSwitchPorts,
	"omada_list_lan_profiles":          (*Server).toolOmadaListLanProfiles,
	"omada_list_gateway_dhcp_users":    (*Server).toolOmadaListGatewayDHCPUsers,
	"omada_get_client_topology":        (*Server).toolOmadaGetClientTopology,
	"omada_dhcp_path":                  (*Server).toolOmadaDHCPPath,
	"omada_get_dhcp_server_info":       (*Server).toolOmadaGetDHCPServerInfo,
	"omada_get_dhcp_snoop_status":      (*Server).toolOmadaGetDHCPSnoopStatus,
	"omada_list_dhcp_snoops":           (*Server).toolOmadaListDHCPSnoops,
	"omada_list_lan_multicasts":        (*Server).toolOmadaListLANMulticasts,
	"omada_plan_port":                  (*Server).toolOmadaPlanPort,
	"omada_apply_port_profile":         (*Server).toolOmadaApplyPortProfile,
	"opnsense_get_info":                (*Server).toolOpnsenseGetInfo,
	"opnsense_list_interfaces":         (*Server).toolOpnsenseListInterfaces,
	"opnsense_list_firewall_rules":     (*Server).toolOpnsenseListFirewallRules,
	"opnsense_list_clients":            (*Server).toolOpnsenseListClients,
	"opnsense_list_port_forward_rules": (*Server).toolOpnsenseListPortForwardRules,
	"opnsense_list_one_to_one_rules":   (*Server).toolOpnsenseListOneToOneRules,
	"opnsense_list_source_nat_rules":   (*Server).toolOpnsenseListSourceNatRules,
	"opnsense_list_aliases":            (*Server).toolOpnsenseListAliases,
	"opnsense_list_services":           (*Server).toolOpnsenseListServices,
	"opnsense_list_gateways":           (*Server).toolOpnsenseListGateways,
	"opnsense_get_nat":                 (*Server).toolOpnsenseGetNAT,
	"opnsense_inventory":               (*Server).toolOpnsenseInventory,
	"opnsense_plan_nat":                (*Server).toolOpnsensePlanNat,
	"opnsense_apply_nat":               (*Server).toolOpnsenseApplyNat,
	"topology":                         (*Server).toolTopology,
}

func (s *Server) toolDiscoverSubnet(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	subnet, _ := args["subnet"].(string)
	if subnet == "" {
		return errResult("subnet parameter is required")
	}
	opts := nmap.DefaultScanOptions
	if t, ok := args["scan_timing"].(float64); ok && t > 0 {
		opts.TimingTemplate = int(t)
	}
	if r, ok := args["scan_min_rate"].(float64); ok && r > 0 {
		opts.MinRate = int(r)
	}
	result, err := nmap.DiscoverWithOptions(ctx, subnet, opts)
	if err != nil {
		return errResult(fmt.Sprintf("discovery failed: %v", err))
	}
	return okResult(toJSON(result))
}

func (s *Server) toolCheckRoutes(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	target, _ := args["target"].(string)
	if target == "" {
		return errResult("target parameter is required")
	}
	return statusResult(s.checkSvc.CheckRoute(ctx, target))
}

func (s *Server) toolCheckVPN(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	target, _ := args["target"].(string)
	if target == "" {
		return errResult("target parameter is required")
	}
	return statusResult(s.checkSvc.CheckVPN(ctx, target))
}

func (s *Server) toolVerifyIsolation(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	from, _ := args["from"].(string)
	to, _ := args["to"].(string)
	if from == "" {
		return errResult("from parameter is required")
	}
	if to == "" {
		return errResult("to parameter is required")
	}
	specFile, _ := args["spec_file"].(string)

	if specFile != "" {
		return s.isolationViaSpec(ctx, specFile, from, to)
	}

	// No spec: ping `to` directly as a bare IP/hostname
	result := models.NewCheckResult("system", "isolation", "local", fmt.Sprintf("%s -> %s", from, to))
	pingResult, err := system.Ping(ctx, to)
	if err != nil {
		result.Status = models.StatusWarn
		result.Summary = fmt.Sprintf("could not determine isolation: %v", err)
	} else {
		result.Observed["reachable"] = pingResult.Reachable
		if pingResult.Reachable {
			result.Status = models.StatusFail
			result.Summary = fmt.Sprintf("isolation violated: %s can reach %s", from, to)
			result.Violations = append(result.Violations, "target is reachable when isolation is expected")
		} else {
			result.Status = models.StatusPass
			result.Summary = fmt.Sprintf("isolation confirmed: %s cannot reach %s", from, to)
		}
	}
	result.Finish()
	return okResult(toJSON(result))
}

// isolationViaSpec runs one isolation assertion against the networks declared
// in specFile, reusing its network definitions for gateway resolution.
func (s *Server) isolationViaSpec(ctx context.Context, specFile, from, to string) toolDispatchResult {
	spec, err := intent.LoadSpec(specFile)
	if err != nil {
		return errResult(fmt.Sprintf("failed to load spec: %v", err))
	}
	miniSpec := &intent.Spec{
		Version:  spec.Version,
		Site:     spec.Site,
		Networks: spec.Networks,
		Assertions: []intent.Assertion{{
			Type:   "isolation",
			From:   from,
			To:     to,
			Expect: "deny",
		}},
	}
	eng := audit.NewEngine(miniSpec)
	eng.Logger = s.logger
	report, err := eng.Run(ctx)
	if err != nil {
		return errResult(fmt.Sprintf("isolation check failed: %v", err))
	}
	if len(report.Findings) == 0 {
		return errResult("no findings returned")
	}
	return okResult(toJSON(report.Findings[0]))
}

func (s *Server) toolRunAudit(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	specFile, _ := args["spec_file"].(string)
	if specFile == "" {
		return errResult("spec_file parameter is required")
	}
	spec, err := intent.LoadSpec(specFile)
	if err != nil {
		return errResult(fmt.Sprintf("failed to load spec: %v", err))
	}
	eng := audit.NewEngine(spec)
	eng.Logger = s.logger
	report, err := eng.Run(ctx)
	if err != nil {
		return errResult(fmt.Sprintf("audit failed: %v", err))
	}
	return okResult(toJSON(report))
}

func (s *Server) toolLoadSpec(_ context.Context, args map[string]interface{}) toolDispatchResult {
	specFile, _ := args["spec_file"].(string)
	if specFile == "" {
		return errResult("spec_file parameter is required")
	}
	spec, err := intent.LoadSpec(specFile)
	if err != nil {
		return errResult(fmt.Sprintf("failed to load spec: %v", err))
	}
	return okResult(toJSON(spec))
}

func (s *Server) toolGetInterfaces(ctx context.Context, _ map[string]interface{}) toolDispatchResult {
	ifaces, err := s.checkSvc.GetInterfaces(ctx)
	if err != nil {
		return errResult(fmt.Sprintf("failed to get interfaces: %v", err))
	}
	return okResult(toJSON(ifaces))
}

func (s *Server) toolPingTarget(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	target, _ := args["target"].(string)
	if target == "" {
		return errResult("target parameter is required")
	}
	pingResult, err := system.Ping(ctx, target)
	if err != nil {
		return errResult(fmt.Sprintf("ping failed: %v", err))
	}
	return okResult(toJSON(pingResult))
}

func (s *Server) toolRunDoctor(_ context.Context, args map[string]interface{}) toolDispatchResult {
	specPath, _ := args["spec_file"].(string)
	var findings []models.CheckResult

	nmapResult := service.NmapCheck()
	if !nmap.Available() {
		nmapResult.Status = models.StatusFail
		nmapResult.Summary = "nmap is not installed or not in PATH"
	}
	findings = append(findings, *nmapResult)

	if specPath != "" {
		findings = append(findings, *service.SpecFileCheck(specPath))
		findings = append(findings, *service.SpecValidCheck(specPath))
		for _, c := range service.ProbeChecks(specPath) {
			findings = append(findings, *c)
		}
	}

	doctorReport := &models.AuditReport{
		Audit:    "doctor",
		Status:   models.ComputeOverallStatus(findings),
		Summary:  models.Tally(findings),
		Findings: findings,
	}
	return okResult(toJSON(doctorReport))
}

func (s *Server) toolProviderList(_ context.Context, _ map[string]interface{}) toolDispatchResult {
	list := providers.List()
	type entry struct {
		Name         string   `json:"name"`
		Capabilities []string `json:"capabilities"`
	}
	out := make([]entry, len(list))
	for i, p := range list {
		out[i] = entry{Name: p.Name(), Capabilities: p.Capabilities()}
	}
	return okResult(toJSON(out))
}

func (s *Server) toolOmadaGetInfo(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.omadaOptionsFromArgs(args, false)
	if msg != "" {
		return errResult(msg)
	}
	info, err := s.omadaSvc.Info(ctx, opts)
	if err != nil {
		return errResult(fmt.Sprintf("omada info request failed: %v", err))
	}
	return okResult(toJSON(info))
}

func (s *Server) toolOmadaListNetworks(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.omadaOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	nets, err := s.omadaSvc.ListNetworks(ctx, opts)
	if err != nil {
		return errResult(fmt.Sprintf("omada networks request failed: %v", err))
	}
	return okResult(toJSON(nets))
}

func (s *Server) toolOmadaListACLs(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.omadaOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	rules, err := s.omadaSvc.ListACLs(ctx, opts)
	if err != nil {
		return errResult(fmt.Sprintf("omada acls request failed: %v", err))
	}
	return okResult(toJSON(rules))
}

func (s *Server) toolOmadaListClients(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.omadaOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	clients, err := s.omadaSvc.ListClients(ctx, opts)
	if err != nil {
		return errResult(fmt.Sprintf("omada clients request failed: %v", err))
	}
	return okResult(toJSON(clients))
}

func (s *Server) toolOmadaListGatewayDHCPUsers(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.omadaOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	mac, _ := args["gateway_mac"].(string)
	if strings.TrimSpace(mac) == "" {
		return errResult("gateway_mac parameter is required")
	}
	rows, err := s.omadaSvc.ListGatewayDHCPUsers(ctx, opts, mac)
	if err != nil {
		return errResult(fmt.Sprintf("omada gateway DHCP users request failed: %v", err))
	}
	return okResult(toJSON(rows))
}

func (s *Server) toolOmadaGetClientTopology(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.omadaOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	mac, _ := args["client_mac"].(string)
	if strings.TrimSpace(mac) == "" {
		return errResult("client_mac parameter is required")
	}
	nodes, err := s.omadaSvc.GetClientTopology(ctx, opts, mac)
	if err != nil {
		return errResult(fmt.Sprintf("omada client topology request failed: %v", err))
	}
	return okResult(toJSON(nodes))
}

func (s *Server) toolOmadaDHCPPath(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.omadaOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	mac, _ := args["client_mac"].(string)
	sw, _ := args["switch_mac"].(string)
	port, _ := args["port"].(float64)
	rep, err := s.omadaSvc.DiagnoseDHCPPath(ctx, opts, service.OmadaDHCPPathRequest{
		ClientMAC: mac, SwitchMAC: sw, Port: int(port),
	})
	if err != nil {
		return errResult(fmt.Sprintf("omada DHCP path request failed: %v", err))
	}
	return okResult(toJSON(rep))
}

func (s *Server) toolOmadaGetDHCPServerInfo(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.omadaOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	id, _ := args["network_id"].(string)
	if strings.TrimSpace(id) == "" {
		return errResult("network_id parameter is required")
	}
	info, err := s.omadaSvc.GetDHCPServerInfo(ctx, opts, id)
	if err != nil {
		return errResult(fmt.Sprintf("omada DHCP server info request failed: %v", err))
	}
	return okResult(toJSON(info))
}

func (s *Server) toolOmadaGetDHCPSnoopStatus(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.omadaOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	st, err := s.omadaSvc.GetDHCPSnoopStatus(ctx, opts)
	if err != nil {
		return errResult(fmt.Sprintf("omada DHCP snooping status request failed: %v", err))
	}
	return okResult(toJSON(st))
}

func (s *Server) toolOmadaListDHCPSnoops(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.omadaOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	rows, err := s.omadaSvc.ListDHCPSnoops(ctx, opts)
	if err != nil {
		return errResult(fmt.Sprintf("omada DHCP snooping rules request failed: %v", err))
	}
	return okResult(toJSON(rows))
}

func (s *Server) toolOmadaListLANMulticasts(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.omadaOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	rows, err := s.omadaSvc.ListLANMulticasts(ctx, opts)
	if err != nil {
		return errResult(fmt.Sprintf("omada LAN multicast rules request failed: %v", err))
	}
	return okResult(toJSON(rows))
}

func (s *Server) toolOmadaInventory(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.omadaOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	inv, err := s.omadaSvc.Inventory(ctx, opts)
	if err != nil {
		return errResult(fmt.Sprintf("omada inventory request failed: %v", err))
	}
	return okResult(toJSON(inv))
}

func (s *Server) toolOmadaImport(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.omadaOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	imp, err := s.omadaSvc.Import(ctx, opts)
	if err != nil {
		return errResult(fmt.Sprintf("omada import request failed: %v", err))
	}
	return okResult(toJSON(imp))
}

func (s *Server) toolOmadaPlan(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.omadaOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	specYAML, _ := args["spec"].(string)
	if specYAML == "" {
		return errResult("spec parameter is required")
	}
	plan, err := s.omadaSvc.Plan(ctx, opts, specYAML)
	if err != nil {
		return errResult(fmt.Sprintf("omada plan request failed: %v", err))
	}
	return okResult(toJSON(plan))
}

func (s *Server) toolOmadaApplyACL(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.omadaOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	fromList := splitCSV(argString(args, "from"))
	toList := splitCSV(argString(args, "to"))
	protocols, perr := parseProtocols(argString(args, "protocols"))
	if perr != "" {
		return errResult(perr)
	}
	req := service.OmadaACLApplyRequest{
		PolicyName: argString(args, "policy_name"),
		From:       fromList,
		To:         toList,
		Action:     argString(args, "action"),
		Scope:      argString(args, "scope"),
		Protocols:  protocols,
		DryRun:     argBoolDefault(args, "dry_run", true),
		PostAudit:  argBoolDefault(args, "post_audit", true),
	}
	if len(fromList) == 0 {
		return errResult("from parameter is required")
	}
	if len(toList) == 0 {
		return errResult("to parameter is required")
	}
	if req.Action == "" {
		return errResult("action parameter is required")
	}
	res, err := s.omadaSvc.ApplyACL(ctx, opts, req)
	if err != nil {
		return errResult(fmt.Sprintf("omada apply request failed: %v", err))
	}
	return okResult(toJSON(res))
}

func (s *Server) toolOmadaListPortForwardings(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.omadaOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	pfs, err := s.omadaSvc.ListPortForwardings(ctx, opts)
	if err != nil {
		return errResult(fmt.Sprintf("omada port forwardings request failed: %v", err))
	}
	return okResult(toJSON(pfs))
}

func (s *Server) toolOmadaListOneToOneNAT(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.omadaOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	rules, err := s.omadaSvc.ListOneToOneNAT(ctx, opts)
	if err != nil {
		return errResult(fmt.Sprintf("omada one-to-one NAT request failed: %v", err))
	}
	return okResult(toJSON(rules))
}

// toolOmadaGetNatSettings reads the Omada ALG and firewall settings and
// returns both in one flat response.
func (s *Server) toolOmadaGetNatSettings(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.omadaOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	type natSettings struct {
		ALG      *service.OmadaALGSettings      `json:"alg"`
		Firewall *service.OmadaFirewallSettings `json:"firewall"`
	}
	alg, err := s.omadaSvc.GetALGSettings(ctx, opts)
	if err != nil {
		return errResult(fmt.Sprintf("omada ALG settings request failed: %v", err))
	}
	fw, err := s.omadaSvc.GetFirewallSettings(ctx, opts)
	if err != nil {
		return errResult(fmt.Sprintf("omada firewall settings request failed: %v", err))
	}
	return okResult(toJSON(natSettings{ALG: alg, Firewall: fw}))
}

func (s *Server) toolOmadaNatFacts(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.omadaOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	facts, err := s.omadaSvc.NatFacts(ctx, opts)
	if err != nil {
		return errResult(fmt.Sprintf("omada nat facts request failed: %v", err))
	}
	return okResult(toJSON(facts))
}

func (s *Server) toolOmadaGetUplinkInfo(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.omadaOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	mac := strings.TrimSpace(argString(args, "device_mac"))
	if mac == "" {
		return errResult("device_mac parameter is required")
	}
	rows, err := s.omadaSvc.GetUplinkInfo(ctx, opts, []string{mac})
	if err != nil {
		return errResult(fmt.Sprintf("omada uplink info request failed: %v", err))
	}
	// The controller omits rows for MACs with no observed uplink; say so
	// explicitly instead of returning a bare empty array.
	if len(rows) == 0 {
		return okResult(toJSON(map[string]string{"mac": mac, "note": "no uplink observed for this MAC"}))
	}
	return okResult(toJSON(rows[0]))
}

func (s *Server) toolOmadaListSwitchPorts(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.omadaOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	ports, err := s.omadaSvc.ListSwitchPorts(ctx, opts, argString(args, "switch_mac"))
	if err != nil {
		return errResult(fmt.Sprintf("omada switch ports request failed: %v", err))
	}
	return okResult(toJSON(ports))
}

func (s *Server) toolOmadaListLanProfiles(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.omadaOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	profiles, err := s.omadaSvc.ListLanProfiles(ctx, opts)
	if err != nil {
		return errResult(fmt.Sprintf("omada lan profiles request failed: %v", err))
	}
	return okResult(toJSON(profiles))
}

func (s *Server) toolOmadaPlanPort(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.omadaOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	req, rmsg := portProfileRequestFromArgs(args)
	if rmsg != "" {
		return errResult(rmsg)
	}
	plan, err := s.omadaSvc.PlanPort(ctx, opts, req)
	if err != nil {
		return errResult(fmt.Sprintf("omada port plan request failed: %v", err))
	}
	return okResult(toJSON(plan))
}

func (s *Server) toolOmadaApplyPortProfile(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.omadaOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	req, rmsg := portProfileRequestFromArgs(args)
	if rmsg != "" {
		return errResult(rmsg)
	}
	res, err := s.omadaSvc.ApplyPortProfile(ctx, opts, req, argBoolDefault(args, "dry_run", true))
	if err != nil {
		return errResult(fmt.Sprintf("omada port profile apply failed: %v", err))
	}
	return okResult(toJSON(res))
}

func (s *Server) toolOpnsenseGetInfo(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.opnsenseOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	info, err := s.opnsenseSvc.Info(ctx, opts)
	if err != nil {
		return errResult(fmt.Sprintf("opnsense info request failed: %v", err))
	}
	return okResult(toJSON(info))
}

func (s *Server) toolOpnsenseListInterfaces(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.opnsenseOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	ifaces, err := s.opnsenseSvc.ListInterfaces(ctx, opts)
	if err != nil {
		return errResult(fmt.Sprintf("opnsense interfaces request failed: %v", err))
	}
	return okResult(toJSON(ifaces))
}

func (s *Server) toolOpnsenseListServices(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.opnsenseOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	svcs, err := s.opnsenseSvc.ListServices(ctx, opts)
	if err != nil {
		return errResult(fmt.Sprintf("opnsense services request failed: %v", err))
	}
	return okResult(toJSON(svcs))
}

func (s *Server) toolOpnsenseListGateways(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.opnsenseOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	gws, err := s.opnsenseSvc.ListGateways(ctx, opts)
	if err != nil {
		return errResult(fmt.Sprintf("opnsense gateways request failed: %v", err))
	}
	return okResult(toJSON(gws))
}

func (s *Server) toolOpnsenseListFirewallRules(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.opnsenseOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	rules, err := s.opnsenseSvc.ListFirewallRules(ctx, opts)
	if err != nil {
		return errResult(fmt.Sprintf("opnsense firewall rules request failed: %v", err))
	}
	return okResult(toJSON(rules))
}

func (s *Server) toolOpnsenseListClients(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.opnsenseOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	clients, err := s.opnsenseSvc.ListClients(ctx, opts)
	if err != nil {
		return errResult(fmt.Sprintf("opnsense clients request failed: %v", err))
	}
	return okResult(toJSON(clients))
}

func (s *Server) toolOpnsenseListPortForwardRules(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.opnsenseOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	rules, err := s.opnsenseSvc.ListPortForwardRules(ctx, opts)
	if err != nil {
		return errResult(fmt.Sprintf("opnsense port forward rules request failed: %v", err))
	}
	return okResult(toJSON(rules))
}

func (s *Server) toolOpnsenseListOneToOneRules(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.opnsenseOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	rules, err := s.opnsenseSvc.ListOneToOneRules(ctx, opts)
	if err != nil {
		return errResult(fmt.Sprintf("opnsense one-to-one rules request failed: %v", err))
	}
	return okResult(toJSON(rules))
}

func (s *Server) toolOpnsenseListSourceNatRules(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.opnsenseOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	rules, err := s.opnsenseSvc.ListSourceNatRules(ctx, opts)
	if err != nil {
		return errResult(fmt.Sprintf("opnsense source NAT rules request failed: %v", err))
	}
	return okResult(toJSON(rules))
}

func (s *Server) toolOpnsenseListAliases(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.opnsenseOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	aliases, err := s.opnsenseSvc.ListAliases(ctx, opts)
	if err != nil {
		return errResult(fmt.Sprintf("opnsense aliases request failed: %v", err))
	}
	return okResult(toJSON(aliases))
}

func (s *Server) toolOpnsenseGetNAT(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.opnsenseOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	nat, err := s.opnsenseSvc.GetNAT(ctx, opts)
	if err != nil {
		return errResult(fmt.Sprintf("opnsense NAT posture request failed: %v", err))
	}
	return okResult(toJSON(nat))
}

func (s *Server) toolOpnsenseInventory(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.opnsenseOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	inv, err := s.opnsenseSvc.Inventory(ctx, opts)
	if err != nil {
		return errResult(fmt.Sprintf("opnsense inventory request failed: %v", err))
	}
	return okResult(toJSON(inv))
}

// opnsenseNatRequestFromArgs assembles the NAT mutation request from tool
// arguments. The returned message is non-empty when a required parameter is
// missing or invalid.
func opnsenseNatRequestFromArgs(args map[string]interface{}) (service.OpnsenseNatApplyRequest, string) {
	req := service.OpnsenseNatApplyRequest{
		Operation:      argString(args, "operation"),
		Action:         argString(args, "action"),
		RuleUUID:       argString(args, "rule_uuid"),
		ToggleDisable:  argBoolDefault(args, "toggle_disable", false),
		AllowDoubleNat: argBoolDefault(args, "allow_double_nat", false),
		DryRun:         argBoolDefault(args, "dry_run", true),
	}
	req.Spec.Interfaces = splitCSV(argString(args, "interfaces"))
	req.Spec.Protocol = argString(args, "protocol")
	req.Spec.Source = argString(args, "source")
	req.Spec.Destination = argString(args, "destination")
	req.Spec.Port = argString(args, "port")
	req.Spec.LocalPort = argString(args, "local_port")
	req.Spec.Target = argString(args, "target")
	req.Spec.Type = argString(args, "type")
	req.Spec.Label = argString(args, "label")
	if req.Operation == "" {
		return req, "operation parameter is required: port_forward, one_to_one, or source_nat"
	}
	action := req.Action
	if action == "" {
		action = "create"
	}
	if action != "create" && req.RuleUUID == "" {
		return req, fmt.Sprintf("rule_uuid is required for action %q", action)
	}
	return req, ""
}

func (s *Server) toolOpnsensePlanNat(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.opnsenseOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	req, merr := opnsenseNatRequestFromArgs(args)
	if merr != "" {
		return errResult(merr)
	}
	plan, err := s.opnsenseSvc.PlanNat(ctx, opts, req)
	if err != nil {
		return errResult(fmt.Sprintf("opnsense plan request failed: %v", err))
	}
	return okResult(toJSON(plan))
}

func (s *Server) toolOpnsenseApplyNat(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := s.opnsenseOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	req, merr := opnsenseNatRequestFromArgs(args)
	if merr != "" {
		return errResult(merr)
	}
	res, err := s.opnsenseSvc.ApplyNat(ctx, opts, req)
	if err != nil {
		return errResult(fmt.Sprintf("opnsense apply request failed: %v", err))
	}
	return okResult(toJSON(res))
}

// toolTopology reports NAT posture across the configured providers. A
// provider is skipped (not an error) when no host is configured for it;
// when both are skipped the call fails with a guidance message.
func (s *Server) toolTopology(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	var (
		omadaOpts *service.OmadaOptions
		opnsOpts  *service.OpnsenseOptions
	)
	if o, msg := s.omadaOptionsFromArgs(subArgs(args, "omada_"), true); msg == "" {
		omadaOpts = &o
	} else if msg != requiredHostMsg {
		return errResult(msg)
	}
	if o, msg := s.opnsenseOptionsFromArgs(subArgs(args, "opnsense_"), true); msg == "" {
		opnsOpts = &o
	} else if msg != requiredHostMsg {
		return errResult(msg)
	}
	if omadaOpts == nil && opnsOpts == nil {
		return errResult("topology requires a host for at least one provider: set omada_host or opnsense_host (or the OMADA_HOST / OPNSENSE_HOST environment variables or the credential store)")
	}
	rep, err := s.topoSvc.Report(ctx, service.TopologyOptions{Omada: omadaOpts, Opnsense: opnsOpts})
	if err != nil {
		return errResult(fmt.Sprintf("topology report failed: %v", err))
	}
	return okResult(toJSON(rep))
}

// subArgs remaps prefixed topology arguments (e.g. omada_host) onto the
// bare keys the per-provider options builders expect (host, client_id, ...).
func subArgs(args map[string]interface{}, prefix string) map[string]interface{} {
	known := []string{"host", "client_id", "client_secret", "site", "api_key", "api_secret", "skip_tls_verify", "ca_cert_path"}
	sub := make(map[string]interface{}, len(known))
	for _, k := range known {
		if v, ok := args[prefix+k]; ok {
			sub[k] = v
		}
	}
	return sub
}
