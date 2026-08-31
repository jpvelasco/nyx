package mcp

import (
	"context"
	"fmt"

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
	"opnsense_get_info":                (*Server).toolOpnsenseGetInfo,
	"opnsense_list_interfaces":         (*Server).toolOpnsenseListInterfaces,
	"opnsense_list_firewall_rules":     (*Server).toolOpnsenseListFirewallRules,
	"opnsense_list_clients":            (*Server).toolOpnsenseListClients,
	"opnsense_list_port_forward_rules": (*Server).toolOpnsenseListPortForwardRules,
	"opnsense_list_one_to_one_rules":   (*Server).toolOpnsenseListOneToOneRules,
	"opnsense_list_source_nat_rules":   (*Server).toolOpnsenseListSourceNatRules,
	"opnsense_list_aliases":            (*Server).toolOpnsenseListAliases,
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
