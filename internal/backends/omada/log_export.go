package omada

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strings"
)

// Log export formats accepted by POST /logs/export.
const (
	// LogExportCSV requests the CSV export. The controller delivers it as a
	// zip archive containing a single .csv file (columns: LOG TYPE, TIME,
	// CONTENT).
	LogExportCSV = 0
	// LogExportXLSX requests the spreadsheet export.
	LogExportXLSX = 1
)

// LogExport is a controller log export: the raw attachment bytes plus the
// filename the controller advertised in Content-Disposition (may be empty
// when the header is absent).
type LogExport struct {
	Filename string
	Data     []byte
}

// ExportLogs requests the controller's log export for the given sites. The
// success response is a binary attachment; JSON envelopes carry errors
// only (e.g. -1600 on controllers without the endpoint, -1 on sites or
// editions where export is disabled).
func (c *Client) ExportLogs(ctx context.Context, siteIDs []string, format int) (LogExport, error) {
	var out LogExport
	if len(siteIDs) == 0 {
		return out, fmt.Errorf("log export requires at least one site id")
	}
	if format != LogExportCSV && format != LogExportXLSX {
		return out, fmt.Errorf("export format must be %d (csv) or %d (xlsx)", LogExportCSV, LogExportXLSX)
	}
	// The payload is a struct of strings and an int, so Marshal cannot fail.
	payload, _ := json.Marshal(struct {
		SiteIDs []string `json:"siteIds"`
		Format  int      `json:"format"`
	}{siteIDs, format})
	filename, data, err := c.doDownloadLocked(ctx, http.MethodPost, c.requestURL("logs/export"), "logs/export", "application/json", payload)
	if err != nil {
		return out, logExportError(err)
	}
	out.Filename = filename
	out.Data = data
	return out, nil
}

// errNoAttachment is returned when the controller answers the export
// request with a JSON envelope instead of the binary attachment. The
// message carries no path or host so it is safe to surface verbatim.
var errNoAttachment = errors.New("the controller returned a JSON response instead of a log export attachment — the export endpoint is not available on this controller")

// logExportError gives a download failure an operator-facing message:
// context errors pass through, structured controller failures keep their
// classified message (code plus guidance), and anything else collapses to
// a generic form so a transport error can never carry the controller
// address.
func logExportError(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("log export: %w", err)
	}
	if errors.Is(err, errNoAttachment) {
		return fmt.Errorf("log export failed: %w", err)
	}
	var api *apiError
	if errors.As(err, &api) {
		return fmt.Errorf("log export failed: %w", err)
	}
	return fmt.Errorf("log export failed: transport or protocol error")
}

// attachmentFilename extracts the filename from a Content-Disposition
// header. Quoted and unquoted forms are accepted; the result is reduced to
// a plain base name so a hostile or malformed header can never steer the
// write path.
func attachmentFilename(disposition string) string {
	_, params, err := mime.ParseMediaType(disposition)
	if err != nil {
		return ""
	}
	name := params["filename"]
	if name == "" {
		return ""
	}
	name = strings.ReplaceAll(name, "\\", "/")
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	return strings.Trim(name, `"'`)
}
