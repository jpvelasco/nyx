package service

import (
	"context"
	"testing"

	"github.com/jpvelasco/nyx/internal/backends/nmap"
	"github.com/jpvelasco/nyx/internal/models"
)

// --- NewCheckService ---

func TestNewCheckService(t *testing.T) {
	svc := NewCheckService()
	if svc == nil {
		t.Fatal("expected non-nil CheckService")
	}
	if svc.Backend == nil {
		t.Error("expected non-nil Backend")
	}
}

func TestNewCheckService_CheckRoute(t *testing.T) {
	svc := NewCheckService()
	result := svc.CheckRoute(context.Background(), "8.8.8.8")
	result.Finish()
	if result.CheckType != "route_check" {
		t.Errorf("expected route_check, got %s", result.CheckType)
	}
}

// --- NmapCheck: not available ---

func TestNmapCheck_NotAvailable(t *testing.T) {
	// Temporarily set PATH to not include nmap
	t.Setenv("PATH", "")

	result := NmapCheck()
	if result.Status != models.StatusFail {
		t.Errorf("expected fail when nmap not found, got %s", result.Status)
	}
	if result.Summary == "" {
		t.Error("expected non-empty summary")
	}
}

// --- NmapCheck: available ---

func TestNmapCheck_AvailableEdge(t *testing.T) {
	if !nmap.Available() {
		t.Skip("nmap not installed or not in PATH")
	}
	result := NmapCheck()
	if result.Status != models.StatusPass {
		t.Errorf("expected pass, got %s", result.Status)
	}
	if result.Summary != "nmap is available" {
		t.Errorf("expected 'nmap is available', got %q", result.Summary)
	}
}
