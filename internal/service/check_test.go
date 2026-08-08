package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jpvelasco/nyx/internal/backends"
	"github.com/jpvelasco/nyx/internal/backends/system"
	"github.com/jpvelasco/nyx/internal/models"
)

// --- CheckRoute ---

func TestCheckRoute_Success(t *testing.T) {
	mock := &backends.MockBackend{
		RouteResult: &system.Route{Device: "eth0", Gateway: "192.168.1.1", Destination: "0.0.0.0/0"},
	}
	svc := &CheckService{Backend: mock}
	result := svc.CheckRoute(context.Background(), "8.8.8.8")
	result.Finish()

	if result.Status != models.StatusPass {
		t.Errorf("expected pass, got %s", result.Status)
	}
	if result.Observed["gateway"] != "192.168.1.1" {
		t.Errorf("expected gateway 192.168.1.1, got %v", result.Observed["gateway"])
	}
	if result.Observed["device"] != "eth0" {
		t.Errorf("expected device eth0, got %v", result.Observed["device"])
	}
	if result.StartedAt.IsZero() || result.FinishedAt.IsZero() {
		t.Error("expected timestamps to be set after Finish()")
	}
}

func TestCheckRoute_Error(t *testing.T) {
	mock := &backends.MockBackend{
		RouteErr: backends.BackendError("no route to host"),
	}
	svc := &CheckService{Backend: mock}
	result := svc.CheckRoute(context.Background(), "8.8.8.8")
	result.Finish()

	if result.Status != models.StatusError {
		t.Errorf("expected error, got %s", result.Status)
	}
	if result.Summary == "" {
		t.Error("expected summary to be set")
	}
}

// --- CheckVPN ---

func TestCheckVPN_ViaTunnel(t *testing.T) {
	mock := &backends.MockBackend{
		RouteResult:        &system.Route{Device: "wg0", Gateway: "10.0.0.1", Destination: "0.0.0.0/0"},
		VPNInterfaceResult: true,
	}
	svc := &CheckService{Backend: mock}
	result := svc.CheckVPN(context.Background(), "8.8.8.8")
	result.Finish()

	if result.Status != models.StatusPass {
		t.Errorf("expected pass for tunnel, got %s", result.Status)
	}
	if result.Observed["via_tunnel"] != true {
		t.Errorf("expected via_tunnel=true, got %v", result.Observed["via_tunnel"])
	}
}

func TestCheckVPN_NotViaTunnel(t *testing.T) {
	mock := &backends.MockBackend{
		RouteResult:        &system.Route{Device: "eth0", Gateway: "192.168.1.1", Destination: "0.0.0.0/0"},
		VPNInterfaceResult: false,
	}
	svc := &CheckService{Backend: mock}
	result := svc.CheckVPN(context.Background(), "8.8.8.8")
	result.Finish()

	if result.Status != models.StatusWarn {
		t.Errorf("expected warn for non-tunnel, got %s", result.Status)
	}
	if result.Observed["via_tunnel"] != false {
		t.Errorf("expected via_tunnel=false, got %v", result.Observed["via_tunnel"])
	}
}

func TestCheckVPN_RouteError(t *testing.T) {
	mock := &backends.MockBackend{
		RouteErr: backends.BackendError("route lookup failed"),
	}
	svc := &CheckService{Backend: mock}
	result := svc.CheckVPN(context.Background(), "8.8.8.8")
	result.Finish()

	if result.Status != models.StatusError {
		t.Errorf("expected error, got %s", result.Status)
	}
}

func TestCheckVPN_InterfaceError(t *testing.T) {
	mock := &backends.MockBackend{
		RouteResult:     &system.Route{Device: "eth0", Gateway: "192.168.1.1", Destination: "0.0.0.0/0"},
		VPNInterfaceErr: backends.BackendError("tunnel interface lookup unsupported"),
	}
	svc := &CheckService{Backend: mock}
	result := svc.CheckVPN(context.Background(), "8.8.8.8")
	result.Finish()

	if result.Status != models.StatusError {
		t.Errorf("expected error, got %s", result.Status)
	}
	if result.Observed["via_tunnel"] != nil {
		t.Errorf("via_tunnel should be unset on error, got %v", result.Observed["via_tunnel"])
	}
}

// --- Ping ---

func TestPing_Reachable(t *testing.T) {
	mock := &backends.MockBackend{
		PingResult: &system.PingResult{Reachable: true},
	}
	svc := &CheckService{Backend: mock}
	result := svc.Ping(context.Background(), "192.168.1.1")
	result.Finish()

	if result.Status != models.StatusPass {
		t.Errorf("expected pass, got %s", result.Status)
	}
	if result.Observed["reachable"] != true {
		t.Errorf("expected reachable=true, got %v", result.Observed["reachable"])
	}
}

func TestPing_NotReachable(t *testing.T) {
	mock := &backends.MockBackend{
		PingResult: &system.PingResult{Reachable: false},
	}
	svc := &CheckService{Backend: mock}
	result := svc.Ping(context.Background(), "192.168.1.999")
	result.Finish()

	if result.Status != models.StatusFail {
		t.Errorf("expected fail, got %s", result.Status)
	}
}

func TestPing_Error(t *testing.T) {
	mock := &backends.MockBackend{
		PingErr: backends.BackendError("ping: bad address"),
	}
	svc := &CheckService{Backend: mock}
	result := svc.Ping(context.Background(), "not-a-host")
	result.Finish()

	if result.Status != models.StatusError {
		t.Errorf("expected error, got %s", result.Status)
	}
}

// --- GetInterfaces ---

func TestGetInterfaces_Success(t *testing.T) {
	expected := []system.Interface{
		{Name: "eth0", Type: "ethernet"},
		{Name: "lo", Type: "loopback"},
	}
	mock := &backends.MockBackend{
		InterfacesResult: expected,
	}
	svc := &CheckService{Backend: mock}
	ifaces, err := svc.GetInterfaces(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ifaces) != 2 {
		t.Errorf("expected 2 interfaces, got %d", len(ifaces))
	}
}

func TestGetInterfaces_Error(t *testing.T) {
	mock := &backends.MockBackend{
		InterfacesErr: backends.BackendError("permission denied"),
	}
	svc := &CheckService{Backend: mock}
	_, err := svc.GetInterfaces(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
}

// --- NmapCheck ---

func TestNmapCheck_Available(t *testing.T) {
	result := NmapCheck()
	// On most systems nmap is either available or not - both are valid outcomes
	// We just verify the result structure is correct
	if result.Tool != "doctor" {
		t.Errorf("expected tool doctor, got %s", result.Tool)
	}
	if result.CheckType != "nmap_installed" {
		t.Errorf("expected checkType nmap_installed, got %s", result.CheckType)
	}
	if result.Status != models.StatusPass && result.Status != models.StatusFail {
		t.Errorf("expected pass or fail, got %s", result.Status)
	}
}

// --- SpecFileCheck ---

func TestSpecFileCheck_Readable(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "test.yaml")
	content := []byte("version: 1\nsite: test\n")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatalf("failed to write temp spec: %v", err)
	}

	result := SpecFileCheck(path)
	if result.Status != models.StatusPass {
		t.Errorf("expected pass, got %s", result.Status)
	}
}

func TestSpecFileCheck_NotFound(t *testing.T) {
	result := SpecFileCheck("/nonexistent/path/to/spec.yaml")
	if result.Status != models.StatusFail {
		t.Errorf("expected fail, got %s", result.Status)
	}
}

// --- SpecValidCheck ---

func TestSpecValidCheck_Valid(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "valid.yaml")
	content := []byte("version: 1\nsite: test\n")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatalf("failed to write temp spec: %v", err)
	}

	result := SpecValidCheck(path)
	if result.Status != models.StatusPass {
		t.Errorf("expected pass, got %s: %s", result.Status, result.Summary)
	}
}

func TestSpecValidCheck_Invalid(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "invalid.yaml")
	content := []byte("version: 99\nsite: test\n")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatalf("failed to write temp spec: %v", err)
	}

	result := SpecValidCheck(path)
	if result.Status != models.StatusFail {
		t.Errorf("expected fail for invalid spec, got %s", result.Status)
	}
}

func TestSpecValidCheck_NotFound(t *testing.T) {
	result := SpecValidCheck("/nonexistent/spec.yaml")
	if result.Status != models.StatusFail {
		t.Errorf("expected fail, got %s", result.Status)
	}
}
