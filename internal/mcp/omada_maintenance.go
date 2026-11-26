package mcp

import (
	"context"
	"errors"
	"math"
	"time"

	"github.com/jpvelasco/nyx/internal/service"
)

// Maintenance reads resolve the operator's configured connection, including the explicit site.
func maintenanceBindings() []operationBinding {
	var bindings []operationBinding
	add := func(name, desc string, props map[string]propSchema, required []string, call func(context.Context, service.OmadaOptions, map[string]interface{}) (any, error)) {
		props["profile"] = propSchema{Type: "string", Description: "Configured Omada credential profile, including site"}
		schema := inputSchema{Type: "object", Properties: props, Required: required}
		bindings = append(bindings, operationBinding{tool: tool{Name: name, Description: desc, InputSchema: schema}, call: func(s *Server, ctx context.Context, args map[string]interface{}) toolDispatchResult {
			for k, value := range args {
				prop, ok := props[k]
				if !ok {
					return errResult("unsupported maintenance argument")
				}
				switch prop.Type {
				case "string":
					if _, ok := value.(string); !ok {
						return errResult(k + " must be a string")
					}
				case "boolean":
					if _, ok := value.(bool); !ok {
						return errResult(k + " must be a boolean")
					}
				case "integer":
					v, ok := value.(float64)
					if !ok || v != math.Trunc(v) || v < 0 || v > math.MaxInt32 {
						return errResult(k + " must be a nonnegative integer")
					}
				}
			}
			for _, k := range required {
				if argString(args, k) == "" {
					return errResult(k + " is required")
				}
			}
			opts, msg := s.omadaOptionsFromArgs(map[string]interface{}{"profile": argString(args, "profile")}, true)
			if msg != "" {
				return errResult("configure credentials for the selected Omada profile")
			}
			if opts.Site == "" {
				return errResult("configure an explicit site for the selected Omada profile")
			}
			opts.CACertPath = s.env("NYX_OMADA_MAINTENANCE_CA")
			res, err := call(ctx, opts, args)
			if err != nil {
				return errResult("maintenance operation was not verified; check the selected profile, target, parameters and permissions")
			}
			return okResult(toJSON(res))
		}})
	}
	svc := service.NewOmadaService()
	add("omada_pending_devices", "List one page of pending devices at the configured site.", map[string]propSchema{"page": {Type: "integer", Description: "Page number, starting at 1"}, "page_size": {Type: "integer", Description: "Rows per page (1 to 100)"}, "include_private_details": {Type: "boolean", Description: "Include the MAC for selecting a device"}}, nil, func(ctx context.Context, opts service.OmadaOptions, a map[string]interface{}) (any, error) {
		return svc.PendingDevices(ctx, opts, argIntDefault(a, "page", 1), argIntDefault(a, "page_size", 25), argBoolDefault(a, "include_private_details", false))
	})
	add("omada_adoption_status", "Preview selected adoption or observe progress after an operator starts it in the controller.", map[string]propSchema{"mac": {Type: "string", Description: "Exact selected device MAC"}, "wait_seconds": {Type: "integer", Description: "Maximum observation time, zero for a single read (0 to 120)"}}, []string{"mac"}, func(ctx context.Context, opts service.OmadaOptions, a map[string]interface{}) (any, error) {
		wait := argIntDefault(a, "wait_seconds", 0)
		if wait < 0 || wait > 120 {
			return nil, errors.New("invalid wait")
		}
		return svc.ObserveAdoption(ctx, opts, argString(a, "mac"), time.Duration(wait)*time.Second)
	})
	add("omada_staged_firmware", "Preview an operator-staged upgrade. An explicitly confirmed reboot also requires verified hardware support.", map[string]propSchema{"reference": {Type: "string", Description: "Opaque reference from nyx omada firmware stage"}, "confirm_reboot": {Type: "boolean", Description: "Explicitly authorize reboot for this staged image and target (default false)"}}, []string{"reference"}, func(ctx context.Context, opts service.OmadaOptions, a map[string]interface{}) (any, error) {
		return svc.UpgradeStagedFirmware(ctx, opts, service.FirmwareStageDir(), argString(a, "reference"), argBoolDefault(a, "confirm_reboot", false))
	})
	return bindings
}
