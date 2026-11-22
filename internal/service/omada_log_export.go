package service

import (
	"context"
	"errors"
	"fmt"
	"os"
	"regexp"

	omadabackend "github.com/jpvelasco/nyx/internal/backends/omada"
)

// OmadaLogExportResult reports where the exported log archive was saved.
type OmadaLogExportResult struct {
	Filename string `json:"filename"`
	Path     string `json:"path"`
	Bytes    int    `json:"bytes"`
}

// logExportDefaultName is the fixed local filename used when the
// controller's attachment name is absent or does not look like the
// controller's own export name.
const logExportDefaultName = "omada-log-export.zip"

// logExportNamePattern is the only attachment name shape the controller
// may choose for the default export path: LogList_<digits>.zip with no
// leading dot and no directory component.
var logExportNamePattern = regexp.MustCompile(`^LogList_[0-9]+\.zip$`)

// defaultLogExportName picks the local filename for an export saved
// without an explicit out path. Controller-supplied names outside the
// strict pattern fall back to a fixed name so a hostile or malformed
// header can never steer the write into another file.
func defaultLogExportName(attachment string) string {
	if logExportNamePattern.MatchString(attachment) {
		return attachment
	}
	return logExportDefaultName
}

// ExportLogs fetches the controller log export for the selected site and
// writes the archive to outPath. When outPath is empty, the attachment
// filename supplied by the controller is used when it matches the
// controller's export name shape, and the archive is created fresh: an
// existing file at the default path is never overwritten.
func (s *OmadaService) ExportLogs(ctx context.Context, opts OmadaOptions, format int, outPath string) (*OmadaLogExportResult, error) {
	export, err := withSession(s, ctx, opts, func(c *omadabackend.Client, site string) (omadabackend.LogExport, error) {
		return c.ExportLogs(ctx, []string{site}, format)
	})
	if err != nil {
		return nil, fmt.Errorf("exporting logs: %w", err)
	}
	path := outPath
	fresh := path == ""
	if fresh {
		path = defaultLogExportName(export.Filename)
	}
	if err := writeLogExport(path, export.Data, fresh); err != nil {
		return nil, fmt.Errorf("saving log export: %w", err)
	}
	return &OmadaLogExportResult{
		Filename: export.Filename,
		Path:     path,
		Bytes:    len(export.Data),
	}, nil
}

// writeLogExport writes data to path. With fresh true the file must not
// exist yet: O_EXCL keeps a hostile name from clobbering an existing
// file or following a symlink. With fresh false the write replaces path,
// the standard behavior for an explicit --out target.
func writeLogExport(path string, data []byte, fresh bool) error {
	if !fresh {
		return os.WriteFile(path, data, 0o600)
	}
	// #nosec G304 — operator-chosen --out path or a validated LogList_<digits>.zip base name
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s already exists — remove it or pass --out for a different path: %w", path, err)
		}
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
