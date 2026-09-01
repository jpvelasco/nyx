package opnsense

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jpvelasco/nyx/internal/logger"
	providers "github.com/jpvelasco/nyx/internal/providers"
	"github.com/jpvelasco/nyx/internal/testutil"
)

// TestNewProviderClientWiresLogger verifies the provider seam is wired: a
// client built from ImportOptions carries the caller's logger, so a retry
// in production lands in the shared log file (before this fix the OPNsense
// seam was dead and operation events were lost). NewClient makes no network
// calls, so the local TLS server URL can be the Host directly.
func TestNewProviderClientWiresLogger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nyx.log")
	l, err := logger.NewSlog(path, 5*1024*1024, 3, slog.LevelDebug)
	if err != nil {
		t.Fatalf("NewSlog: %v", err)
	}
	defer logger.CloseSlog(l)

	// The handler always 503s, so every request ends in a retry event.
	_, ts := newTestClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		testutil.WriteBody(w, systemInfoJSON)
	}))

	// NewClient expects a bare host:port (do() prefixes https://).
	c := newProviderClient(providers.ImportOptions{
		Host:          strings.TrimPrefix(ts.URL, "https://"),
		Logger:        l,
		SkipTLSVerify: true,
	})
	c.retryBase = 0 // no backoff sleep in tests
	resp, err := c.do(context.Background(), http.MethodGet, "/diagnostics/system/system_information", nil)
	if err == nil || resp != nil {
		t.Fatalf("do: err=%v resp=%v, want persistent 503 error", err, resp != nil)
	}

	data, err := os.ReadFile(path) // nosemgrep: go_filesystem_rule-fileread
	if err != nil {
		t.Fatalf("reading log: %v", err)
	}
	text := string(data)
	for _, want := range []string{`"msg":"opnsense"`, `"event":"retry"`, `"method":"GET"`} {
		if !strings.Contains(text, want) {
			t.Errorf("log missing %s; got:\n%s", want, text)
		}
	}
	if strings.Contains(text, "secret") {
		t.Errorf("log leaked the API secret; got:\n%s", text)
	}
}
