package service

import (
	"context"
	"fmt"
	"os"

	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
)

// OmadaLogExportResult reports where the exported log archive was saved.
type OmadaLogExportResult struct {
	Filename string `json:"filename"`
	Path     string `json:"path"`
	Bytes    int    `json:"bytes"`
}

// ExportLogs fetches the controller log export for the selected site and
// writes the archive to outPath. When outPath is empty, the attachment
// filename supplied by the controller is used, falling back to a default
// base name.
func (s *OmadaService) ExportLogs(ctx context.Context, opts OmadaOptions, format int, outPath string) (*OmadaLogExportResult, error) {
	export, err := withSession(s, ctx, opts, func(c *omadabackend.Client, site string) (omadabackend.LogExport, error) {
		return c.ExportLogs(ctx, []string{site}, format)
	})
	if err != nil {
		return nil, fmt.Errorf("exporting logs: %w", err)
	}
	path := outPath
	if path == "" {
		path = export.Filename
	}
	if path == "" {
		path = "omada-log-export.zip"
	}
	if err := os.WriteFile(path, export.Data, 0o600); err != nil {
		return nil, fmt.Errorf("saving log export: %w", err)
	}
	return &OmadaLogExportResult{
		Filename: export.Filename,
		Path:     path,
		Bytes:    len(export.Data),
	}, nil
}
