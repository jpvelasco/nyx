package mcp

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jpvelasco/nyx/internal/providers/opnsense"
	"github.com/jpvelasco/nyx/internal/service"
	"github.com/jpvelasco/nyx/internal/snapshot"
)

// Diagnostic reads share the typed service methods used by the CLI and return a bounded page to MCP.
func diagnosticBindings() []operationBinding {
	type omadaRead func(context.Context, service.OmadaOptions, map[string]interface{}, diagnosticWindow) (any, error)
	omadaTool := func(name, description string, extra map[string]propSchema, read omadaRead) operationBinding {
		if extra == nil {
			extra = map[string]propSchema{}
		}
		extra["offset"] = propSchema{Type: "integer", Description: "First row to return (default 0)"}
		extra["limit"] = propSchema{Type: "integer", Description: "Maximum rows to return (default 50, maximum 200)"}
		return operationBinding{tool: tool{Name: name, Description: description, InputSchema: omadaToolSchemaExtra(extra, nil)}, call: func(s *Server, ctx context.Context, args map[string]interface{}) toolDispatchResult {
			w, err := diagnosticPage(args)
			if err != nil {
				return errResult(err.Error())
			}
			opts, msg := s.omadaOptionsFromArgs(args, true)
			if msg != "" {
				return errResult(msg)
			}
			data, err := read(ctx, opts, args, w)
			if err != nil {
				return diagnosticFailure(err)
			}
			return untrustedDataResult(data, "Controller diagnostics")
		}}
	}
	svc := service.NewOmadaService()
	return []operationBinding{
		omadaTool("omada_ap_channel_info", "Read current channels and channel candidates for site access points.", map[string]propSchema{"include_private_details": {Type: "boolean", Description: "Include AP names and MAC addresses"}}, func(ctx context.Context, opts service.OmadaOptions, args map[string]interface{}, w diagnosticWindow) (any, error) {
			return svc.APChannelsPage(ctx, opts, w.offset, w.limit, argBoolDefault(args, "include_private_details", false))
		}),
		omadaTool("omada_wlan_optimization", "Read site optimization history or the per-AP diagnostics for one history ID.", map[string]propSchema{"history_id": {Type: "string", Description: "Return diagnostics for this run"}}, func(ctx context.Context, opts service.OmadaOptions, args map[string]interface{}, w diagnosticWindow) (any, error) {
			if id := argString(args, "history_id"); id != "" {
				detail, err := svc.GetWLANOptimizationHistory(ctx, opts, id)
				if err != nil {
					return nil, err
				}
				return struct {
					Success int                                        `json:"success_devices"`
					Failed  int                                        `json:"fail_devices"`
					APs     diagnosticResult[service.WLANAPDiagnostic] `json:"aps"`
				}{detail.SuccessDevices, detail.FailDevices, diagnosticRows(service.WLANAPDiagnostics(detail), w)}, nil
			}
			rows, err := svc.ListWLANOptimizationHistory(ctx, opts)
			if err != nil {
				return nil, err
			}
			return diagnosticRows(service.WLANRunDiagnostics(rows), w), nil
		}),
		omadaTool("omada_site_config_drift", "Compare this site's current configuration with its saved private baseline.", nil, func(ctx context.Context, opts service.OmadaOptions, _ map[string]interface{}, w diagnosticWindow) (any, error) {
			state, err := svc.ReadSiteConfig(ctx, opts)
			if err != nil {
				return nil, err
			}
			changes, err := snapshot.CompareOmadaSiteConfig(state)
			if err != nil {
				return nil, err
			}
			return diagnosticRows(changes, w), nil
		}),
		{tool: tool{Name: "omada_controller_firmware", Description: "Read the hardware controller's running version and vendor update status.", InputSchema: omadaToolSchema()}, call: func(s *Server, ctx context.Context, args map[string]interface{}) toolDispatchResult {
			opts, msg := s.omadaOptionsFromArgs(args, true)
			if msg != "" {
				return errResult(msg)
			}
			v, err := svc.ControllerFirmware(ctx, opts)
			if err != nil {
				return diagnosticFailure(err)
			}
			return untrustedDataResult(v, "Controller firmware status")
		}},
		stateInspectionBinding(),
	}
}

type diagnosticWindow struct{ offset, limit int }
type diagnosticResult[T any] struct {
	Rows   []T `json:"rows"`
	Total  int `json:"total"`
	Offset int `json:"offset"`
}

func diagnosticRows[T any](rows []T, w diagnosticWindow) diagnosticResult[T] {
	start := min(w.offset, len(rows))
	end := start + min(w.limit, len(rows)-start)
	result := append([]T{}, rows[start:end]...)
	return diagnosticResult[T]{Rows: result, Total: len(rows), Offset: w.offset}
}
func diagnosticPage(args map[string]interface{}) (diagnosticWindow, error) {
	offset, err := diagnosticInteger(args, "offset", 0, 0, 1_000_000)
	if err != nil {
		return diagnosticWindow{}, err
	}
	limit, err := diagnosticInteger(args, "limit", 50, 1, 200)
	return diagnosticWindow{offset, limit}, err
}

// diagnosticInteger validates JSON integer inputs before narrowing to an int.
func diagnosticInteger(args map[string]interface{}, key string, def, minValue, maxValue int) (int, error) {
	v, ok := args[key]
	if !ok {
		return def, nil
	}
	n, ok := v.(float64)
	if !ok || n < float64(minValue) || n > float64(maxValue) || n != float64(int(n)) {
		return 0, fmt.Errorf("%s must be an integer between %d and %d", key, minValue, maxValue)
	}
	return int(n), nil
}
func diagnosticFailure(err error) toolDispatchResult {
	if errors.Is(err, snapshot.ErrNoOmadaSiteBaseline) {
		return errResult(snapshot.ErrNoOmadaSiteBaseline.Error())
	}
	return errResult("diagnostic read failed: " + service.DiagnosticAccess(err))
}
func stateInspectionBinding() operationBinding {
	props := map[string]propSchema{
		"search": {Type: "string", Description: "State table search tokens"}, "rule_id": {Type: "string", Description: "Limit rows to this pf rule ID"}, "sort": {Type: "string", Description: "Sort one field as field:asc or field:desc"},
		"page": {Type: "integer", Description: "Page number, starting at 1"}, "page_size": {Type: "integer", Description: "Rows per page (default 50, maximum 200)"}, "include_private_details": {Type: "boolean", Description: "Include raw state rows with endpoints and identifiers"},
	}
	return operationBinding{tool: tool{Name: "opnsense_query_states", Description: "Inspect one page of the firewall state table scoped to a search or rule ID.", InputSchema: opnsenseToolSchemaExtra(props, nil)}, call: func(s *Server, ctx context.Context, args map[string]interface{}) toolDispatchResult {
		opts, msg := s.opnsenseOptionsFromArgs(args, true)
		if msg != "" {
			return errResult(msg)
		}
		q := opnsense.StateQuery{Search: strings.TrimSpace(argString(args, "search")), RuleID: strings.TrimSpace(argString(args, "rule_id"))}
		if q.Search == "" && q.RuleID == "" {
			return errResult("supply a search or rule_id to scope state inspection")
		}
		var err error
		q.Page, err = diagnosticInteger(args, "page", 1, 1, 1_000_000)
		if err != nil {
			return errResult(err.Error())
		}
		q.PageSize, err = diagnosticInteger(args, "page_size", 50, 1, 200)
		if err != nil {
			return errResult(err.Error())
		}
		if err := q.SetSort(argString(args, "sort")); err != nil {
			return errResult(err.Error())
		}
		page, err := service.NewOpnsenseService().QueryStates(ctx, opts, q)
		if err != nil {
			return diagnosticFailure(err)
		}
		if len(page.Rows) > q.PageSize {
			return errResult("firewall returned more states than requested")
		}
		if !argBoolDefault(args, "include_private_details", false) {
			return okResult(toJSON(map[string]int{"total": page.Total, "page": page.Page, "matched_on_page": len(page.Rows)}))
		}
		return untrustedDataResult(page, "State table rows")
	}}
}
