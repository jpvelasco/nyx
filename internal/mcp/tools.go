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
	"discover_subnet":              (*Server).toolDiscoverSubnet,
	"check_routes":                 (*Server).toolCheckRoutes,
	"check_vpn":                    (*Server).toolCheckVPN,
	"verify_isolation":             (*Server).toolVerifyIsolation,
	"run_audit":                    (*Server).toolRunAudit,
	"load_spec":                    (*Server).toolLoadSpec,
	"get_interfaces":               (*Server).toolGetInterfaces,
	"ping_target":                  (*Server).toolPingTarget,
	"run_doctor":                   (*Server).toolRunDoctor,
	"provider_list":                (*Server).toolProviderList,
	"omada_get_info":               (*Server).toolOmadaGetInfo,
	"omada_list_networks":          (*Server).toolOmadaListNetworks,
	"omada_list_acls":              (*Server).toolOmadaListACLs,
	"omada_list_clients":           (*Server).toolOmadaListClients,
	"omada_inventory":              (*Server).toolOmadaInventory,
	"omada_import":                 (*Server).toolOmadaImport,
	"omada_plan":                   (*Server).toolOmadaPlan,
	"omada_apply_acl":              (*Server).toolOmadaApplyACL,
	"opnsense_get_info":            (*Server).toolOpnsenseGetInfo,
	"opnsense_list_interfaces":     (*Server).toolOpnsenseListInterfaces,
	"opnsense_list_firewall_rules": (*Server).toolOpnsenseListFirewallRules,
	"opnsense_list_clients":        (*Server).toolOpnsenseListClients,
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
	opts, msg := omadaOptionsFromArgs(args, false)
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
	opts, msg := omadaOptionsFromArgs(args, true)
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
	opts, msg := omadaOptionsFromArgs(args, true)
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
	opts, msg := omadaOptionsFromArgs(args, true)
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
	opts, msg := omadaOptionsFromArgs(args, true)
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
	opts, msg := omadaOptionsFromArgs(args, true)
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
	opts, msg := omadaOptionsFromArgs(args, true)
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
	opts, msg := omadaOptionsFromArgs(args, true)
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

func (s *Server) toolOpnsenseGetInfo(ctx context.Context, args map[string]interface{}) toolDispatchResult {
	opts, msg := opnsenseOptionsFromArgs(args, true)
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
	opts, msg := opnsenseOptionsFromArgs(args, true)
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
	opts, msg := opnsenseOptionsFromArgs(args, true)
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
	opts, msg := opnsenseOptionsFromArgs(args, true)
	if msg != "" {
		return errResult(msg)
	}
	clients, err := s.opnsenseSvc.ListClients(ctx, opts)
	if err != nil {
		return errResult(fmt.Sprintf("opnsense clients request failed: %v", err))
	}
	return okResult(toJSON(clients))
}
