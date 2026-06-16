// Package omadaprovider implements the providers.Provider interface for TP-Link Omada SDN controllers (v6+).
package omadaprovider

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jpvelasco/nyx/internal/audit"
	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
	"github.com/jpvelasco/nyx/internal/models"
	providers "github.com/jpvelasco/nyx/internal/providers"
)

// OmadaProvider implements providers.Provider for TP-Link Omada SDN controllers.
type OmadaProvider struct{}

// Name returns the provider identifier "omada".
func (o *OmadaProvider) Name() string { return "omada" }

// Capabilities lists the supported operations for this provider.
func (o *OmadaProvider) Capabilities() []string {
	return []string{"info", "import", "check"}
}

// Info returns basic controller information without requiring authentication.
func (o *OmadaProvider) Info(ctx context.Context, opts providers.ImportOptions) (*providers.ProviderInfo, error) {
	client, err := omadabackend.NewClient(ctx, opts.Host, opts.SkipTLSVerify, opts.CACertPath)
	if err != nil {
		return nil, fmt.Errorf("connecting to omada controller: %w", err)
	}
	info := client.Info()
	return &providers.ProviderInfo{
		Provider: "omada",
		Host:     opts.Host,
		Version:  info.ControllerVer,
		Extra: map[string]string{
			"api_version": info.APIVer,
			"omada_cid":   info.OmadaCID,
		},
	}, nil
}

// ImportSpec imports networks, policies, and clients from the Omada controller and returns a generated intent spec.
func (o *OmadaProvider) ImportSpec(ctx context.Context, opts providers.ImportOptions) (*providers.ImportResult, error) {
	result, err := omadabackend.ImportSpec(ctx, opts.Host, opts.Username, opts.Password, opts.Site, opts.Debug, opts.SkipTLSVerify, opts.CACertPath)
	if err != nil {
		return nil, err
	}
	return &providers.ImportResult{
		Spec: result.Spec,
		ProviderInfo: providers.ProviderInfo{
			Provider: "omada",
			Host:     opts.Host,
			Version:  result.ControllerVersion,
		},
		NetworkCount: result.NetworkCount,
		PolicyCount:  result.ACLRuleCount,
		ClientCount:  result.ClientCount,
		Warnings:     result.Warnings,
	}, nil
}

// Check imports a spec from the controller and runs an audit against it.
func (o *OmadaProvider) Check(ctx context.Context, opts providers.ImportOptions) (*providers.AuditResult, error) {
	imported, err := o.ImportSpec(ctx, opts)
	if err != nil {
		return nil, err
	}
	engine := audit.NewEngine(imported.Spec)
	report, err := engine.Run(ctx)
	if err != nil {
		return nil, fmt.Errorf("audit failed: %w", err)
	}
	return &providers.AuditResult{
		Report:   report,
		Warnings: imported.Warnings,
	}, nil
}

// CheckACL verifies that an ACL policy is enforced (or not) on the Omada controller.
func (o *OmadaProvider) CheckACL(ctx context.Context, req providers.ACLCheckRequest, opts providers.ImportOptions) (*models.CheckResult, error) {
	result := models.NewCheckResult("omada", "acl_check", "omada", req.PolicyName)

	client, err := omadabackend.NewClient(ctx, opts.Host, opts.SkipTLSVerify, opts.CACertPath)
	if err != nil {
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("failed to connect to Omada: %v", err)
		result.Finish()
		return result, nil
	}
	if err := client.Login(ctx, opts.Username, opts.Password); err != nil {
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("Omada login failed: %v", err)
		result.Finish()
		return result, nil
	}
	defer client.Logout(ctx)

	rules, err := client.GetACLRules(ctx, opts.Site)
	if err != nil {
		result.Status = models.StatusError
		result.Summary = fmt.Sprintf("failed to fetch ACL rules: %v", err)
		result.Finish()
		return result, nil
	}
	gwRules, _ := client.GetGatewayACLRules(ctx, opts.Site) // best-effort, don't fail on gateway rule fetch
	allRules := append(rules, gwRules...)

	// Check if a matching ACL rule exists
	found := false
	for _, rule := range allRules {
		if !rule.Status {
			continue // skip disabled rules
		}
		fromMatch := rule.SourceName == req.From || strings.EqualFold(rule.SourceName, req.From)
		toMatch := rule.DestName == req.To || strings.EqualFold(rule.DestName, req.To)
		actionMatch := (req.Action == "deny" && rule.Policy == "drop") ||
			(req.Action == "allow" && rule.Policy == "accept")
		if fromMatch && toMatch && actionMatch {
			found = true
			break
		}
	}

	rulesJSON, _ := json.Marshal(allRules)
	result.Evidence = append(result.Evidence, string(rulesJSON))
	result.Observed["rule_count"] = len(allRules)
	result.Expected["policy"] = req.PolicyName
	result.Expected["expect"] = "enforced"

	if req.ExpectEnforced && found {
		result.Status = models.StatusPass
		result.Summary = fmt.Sprintf("ACL policy %q is enforced in Omada", req.PolicyName)
	} else if req.ExpectEnforced && !found {
		result.Status = models.StatusFail
		result.Summary = fmt.Sprintf("ACL policy %q is NOT enforced in Omada", req.PolicyName)
		result.Violations = append(result.Violations,
			fmt.Sprintf("no matching ACL rule found for policy %q (%s → %s %s)", req.PolicyName, req.From, req.To, req.Action))
	} else if !req.ExpectEnforced && !found {
		result.Status = models.StatusPass
		result.Summary = fmt.Sprintf("ACL policy %q is correctly not enforced", req.PolicyName)
	} else {
		result.Status = models.StatusFail
		result.Summary = fmt.Sprintf("ACL policy %q is enforced but expected not_enforced", req.PolicyName)
	}

	result.Finish()
	return result, nil
}

var _ providers.Provider = (*OmadaProvider)(nil)

func init() {
	_ = providers.Register(&OmadaProvider{})
}
