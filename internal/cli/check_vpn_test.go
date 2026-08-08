package cli

import (
	"testing"

	"github.com/jpvelasco/nyx/internal/models"
)

func resultWithTunnel(status models.Status, viaTunnel bool) *models.CheckResult {
	r := models.NewCheckResult("system", "vpn_route", "local", "8.8.8.8")
	r.Status = status
	r.Observed["device"] = "wg0"
	r.Observed["via_tunnel"] = viaTunnel
	return r
}

func TestApplyVPNExpect_NoExpectKeepsStatus(t *testing.T) {
	r := resultWithTunnel(models.StatusWarn, false)
	applyVPNExpect(r, "")
	if r.Status != models.StatusWarn {
		t.Errorf("status changed without --expect: %s", r.Status)
	}
}

func TestApplyVPNExpect_ErrorsLeftUntouched(t *testing.T) {
	r := models.NewCheckResult("system", "vpn_route", "local", "8.8.8.8")
	r.Status = models.StatusError
	r.Summary = "failed to classify interface"
	applyVPNExpect(r, "full-tunnel")
	if r.Status != models.StatusError {
		t.Errorf("error status overwritten: %s", r.Status)
	}
}

func TestApplyVPNExpect_FullTunnel(t *testing.T) {
	via := resultWithTunnel(models.StatusPass, true)
	applyVPNExpect(via, "full-tunnel")
	if via.Status != models.StatusPass {
		t.Errorf("full-tunnel via tunnel: got %s, want pass", via.Status)
	}

	notVia := resultWithTunnel(models.StatusWarn, false)
	applyVPNExpect(notVia, "full-tunnel")
	if notVia.Status != models.StatusFail {
		t.Errorf("full-tunnel not via tunnel: got %s, want fail", notVia.Status)
	}
	if len(notVia.Violations) == 0 {
		t.Error("expected violation for full-tunnel expectation miss")
	}
}

func TestApplyVPNExpect_SplitTunnel(t *testing.T) {
	via := resultWithTunnel(models.StatusPass, true)
	applyVPNExpect(via, "split-tunnel")
	if via.Status != models.StatusFail {
		t.Errorf("split-tunnel via tunnel: got %s, want fail", via.Status)
	}
	if len(via.Violations) == 0 {
		t.Error("expected violation for split-tunnel expectation miss")
	}

	notVia := resultWithTunnel(models.StatusWarn, false)
	applyVPNExpect(notVia, "split-tunnel")
	if notVia.Status != models.StatusPass {
		t.Errorf("split-tunnel not via tunnel: got %s, want pass", notVia.Status)
	}
}
