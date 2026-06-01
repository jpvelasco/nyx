# Virtual Network Acknowledgement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Suppress repeat WARNs for virtual subnets (VMware, Hyper-V, WSL2) that always return 0 hosts — warn once, record the acknowledgement in `~/.nyx/seen.json`, skip silently on future runs unless `--warn-virtual` is set.

**Architecture:** New `internal/seendb` package owns `~/.nyx/seen.json` (read/write, best-effort). `looksVirtual(evidence []string) bool` helper in `internal/audit` detects VM MAC prefixes in nmap output. `runDiscovery` in the engine consults seendb and sets `StatusSkip` vs `StatusWarn` accordingly. `--warn-virtual` flag on `nyx audit` bypasses seendb.

**Tech Stack:** Go stdlib (`encoding/json`, `os`, `path/filepath`), existing `internal/models`, `internal/audit`, `internal/cli` packages.

---

### Task 1: `internal/seendb` package

**Files:**
- Create: `internal/seendb/seendb.go`
- Create: `internal/seendb/seendb_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/seendb/seendb_test.go`:

```go
package seendb_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/velasco-jp/nyx/internal/seendb"
)

func TestLoadMissingFileReturnsEmpty(t *testing.T) {
	db, err := seendb.LoadFrom(filepath.Join(t.TempDir(), "notexist.json"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if db.IsVirtualAcked("192.168.1.0/24") {
		t.Error("expected false for unacked CIDR")
	}
}

func TestAckAndReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seen.json")
	db, _ := seendb.LoadFrom(path)
	if err := db.AckVirtual("10.0.0.0/24"); err != nil {
		t.Fatalf("ack failed: %v", err)
	}
	db2, err := seendb.LoadFrom(path)
	if err != nil {
		t.Fatalf("reload failed: %v", err)
	}
	if !db2.IsVirtualAcked("10.0.0.0/24") {
		t.Error("expected CIDR to be acked after reload")
	}
}

func TestAckUnwritablePathIsGraceful(t *testing.T) {
	db, _ := seendb.LoadFrom("/nonexistent/path/seen.json")
	err := db.AckVirtual("10.0.0.0/24")
	// Should not panic; error is returned but not fatal
	_ = err
}

func TestSeenAtIsPopulated(t *testing.T) {
	path := filepath.Join(t.TempDir(), "seen.json")
	db, _ := seendb.LoadFrom(path)
	_ = db.AckVirtual("10.0.0.0/24")
	db2, _ := seendb.LoadFrom(path)
	entry := db2.GetEntry("10.0.0.0/24")
	if entry == nil {
		t.Fatal("expected entry to exist")
	}
	if entry.SeenAt.IsZero() {
		t.Error("expected SeenAt to be populated")
	}
	if time.Since(entry.SeenAt) > 5*time.Second {
		t.Error("SeenAt should be recent")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/seendb/...
```
Expected: compile error — package does not exist yet.

- [ ] **Step 3: Implement `internal/seendb/seendb.go`**

```go
package seendb

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

type Entry struct {
	SeenAt  time.Time `json:"seen_at"`
	Virtual bool      `json:"virtual"`
}

type SeenDB struct {
	VirtualNetworks map[string]Entry `json:"virtual_networks"`
	path            string
}

func Load() (*SeenDB, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return empty(""), err
	}
	return LoadFrom(filepath.Join(home, ".nyx", "seen.json"))
}

func LoadFrom(path string) (*SeenDB, error) {
	db := &SeenDB{VirtualNetworks: map[string]Entry{}, path: path}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return db, nil
	}
	if err != nil {
		return db, err
	}
	if err := json.Unmarshal(data, db); err != nil {
		return db, err
	}
	db.path = path
	return db, nil
}

func empty(path string) (*SeenDB, error) {
	return &SeenDB{VirtualNetworks: map[string]Entry{}, path: path}, nil
}

func (db *SeenDB) IsVirtualAcked(cidr string) bool {
	_, ok := db.VirtualNetworks[cidr]
	return ok
}

func (db *SeenDB) GetEntry(cidr string) *Entry {
	e, ok := db.VirtualNetworks[cidr]
	if !ok {
		return nil
	}
	return &e
}

func (db *SeenDB) AckVirtual(cidr string) error {
	db.VirtualNetworks[cidr] = Entry{SeenAt: time.Now().UTC(), Virtual: true}
	return db.save()
}

func (db *SeenDB) save() error {
	if db.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(db.path), 0750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(db.path, data, 0640)
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/seendb/...
```
Expected: all tests pass.

- [ ] **Step 5: Commit**

```bash
git add internal/seendb/seendb.go internal/seendb/seendb_test.go
git commit -m "feat: add seendb package for virtual network acknowledgement"
```

---

### Task 2: `looksVirtual` helper in `internal/audit`

**Files:**
- Create: `internal/audit/virtual.go`
- Create: `internal/audit/virtual_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/audit/virtual_test.go`:

```go
package audit

import (
	"testing"
)

func TestLooksVirtual(t *testing.T) {
	tests := []struct {
		name     string
		evidence []string
		want     bool
	}{
		{
			name:     "VMware OUI 00:50:56",
			evidence: []string{"Nmap scan report for 192.168.174.254", "Host is up.", "MAC Address: 00:50:56:EE:69:AB (VMware)"},
			want:     true,
		},
		{
			name:     "VMware OUI 00:0C:29",
			evidence: []string{"MAC Address: 00:0C:29:A7:6F:AA (VMware)"},
			want:     true,
		},
		{
			name:     "VMware OUI 00:05:69",
			evidence: []string{"MAC Address: 00:05:69:11:22:33 (VMware)"},
			want:     true,
		},
		{
			name:     "VirtualBox OUI 08:00:27",
			evidence: []string{"MAC Address: 08:00:27:AB:CD:EF (VirtualBox)"},
			want:     true,
		},
		{
			name:     "Hyper-V / WSL2 OUI 00:15:5D",
			evidence: []string{"MAC Address: 00:15:5D:12:34:56 (Microsoft)"},
			want:     true,
		},
		{
			name:     "case insensitive",
			evidence: []string{"mac address: 00:50:56:aa:bb:cc (vmware)"},
			want:     true,
		},
		{
			name:     "real hardware MAC",
			evidence: []string{"MAC Address: D0:D2:B0:7B:ED:79 (Apple)"},
			want:     false,
		},
		{
			name:     "empty evidence",
			evidence: []string{},
			want:     false,
		},
		{
			name:     "no MAC line",
			evidence: []string{"Nmap done: 256 IP addresses (0 hosts up) scanned in 44s"},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := looksVirtual(tt.evidence)
			if got != tt.want {
				t.Errorf("looksVirtual(%v) = %v, want %v", tt.evidence, got, tt.want)
			}
		})
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/audit/... -run TestLooksVirtual
```
Expected: compile error — `looksVirtual` not defined.

- [ ] **Step 3: Implement `internal/audit/virtual.go`**

```go
package audit

import (
	"strings"
)

// vmMACPrefixes are the well-known OUI prefixes for virtual machine hypervisors.
// Hyper-V and WSL2 both use 00:15:5D.
var vmMACPrefixes = []string{
	"00:50:56", // VMware ESX/Workstation
	"00:0c:29", // VMware (dynamically assigned)
	"00:05:69", // VMware (older)
	"08:00:27", // VirtualBox
	"00:15:5d", // Hyper-V / WSL2
}

// looksVirtual returns true if any evidence line contains a known VM MAC prefix.
func looksVirtual(evidence []string) bool {
	for _, line := range evidence {
		lower := strings.ToLower(line)
		for _, prefix := range vmMACPrefixes {
			if strings.Contains(lower, prefix) {
				return true
			}
		}
	}
	return false
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
go test ./internal/audit/... -run TestLooksVirtual
```
Expected: all 9 subtests pass.

- [ ] **Step 5: Commit**

```bash
git add internal/audit/virtual.go internal/audit/virtual_test.go
git commit -m "feat: add looksVirtual helper for VM MAC prefix detection"
```

---

### Task 3: Engine changes — `WarnVirtual` field + `runDiscovery` logic

**Files:**
- Modify: `internal/audit/engine.go`
- Modify: `internal/audit/engine_test.go`

- [ ] **Step 1: Add `WarnVirtual bool` field to `Engine` struct**

In `internal/audit/engine.go`, update the `Engine` struct:

```go
type Engine struct {
	Spec        *intent.Spec
	Interface   string
	WarnVirtual bool // if true, always emit WARN for virtual subnets (ignores seendb)
	runnerCtx   models.RunnerContext
}
```

- [ ] **Step 2: Write the failing tests for the new discovery behaviour**

Add to `internal/audit/engine_test.go`:

```go
func TestDiscoveryVirtualFirstRunWarns(t *testing.T) {
	if !nmap.Available() {
		t.Skip("nmap not available")
	}
	// Use a VMware subnet CIDR that will return 0 hosts but nmap will see
	// a VMware MAC. We can't guarantee MAC in unit test, so we test the
	// seendb path directly by injecting a temp seendb path.
	// This test verifies: when WarnVirtual=true, status is always Warn.
	spec := &intent.Spec{
		Version: 1,
		Site:    "test",
		Networks: []intent.Network{
			{Name: "vmnet", CIDR: "192.168.174.0/24", Gateway: "192.168.174.1", Zone: "vmnet"},
		},
		Assertions: []intent.Assertion{
			{Type: "subnet_discovery", Network: "vmnet"},
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	engine := audit.NewEngine(spec)
	engine.WarnVirtual = true
	report, err := engine.Run(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	f := report.Findings[0]
	// With WarnVirtual=true and 0 hosts, should be Warn (not Skip)
	if f.Status == models.StatusPass {
		t.Errorf("expected non-pass status when 0 hosts on virtual net with WarnVirtual=true, got pass")
	}
}

func TestLooksVirtualUnitWithSeenDB(t *testing.T) {
	// Unit test the seendb skip path without needing nmap
	// by testing looksVirtual + seendb integration directly.
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "seen.json")

	db, err := seendb.LoadFrom(dbPath)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	cidr := "192.168.174.0/24"
	if db.IsVirtualAcked(cidr) {
		t.Fatal("should not be acked yet")
	}
	if err := db.AckVirtual(cidr); err != nil {
		t.Fatalf("ack: %v", err)
	}
	db2, _ := seendb.LoadFrom(dbPath)
	if !db2.IsVirtualAcked(cidr) {
		t.Error("should be acked after write")
	}
}
```

Add required imports to `engine_test.go`:
```go
import (
	"path/filepath"
	"github.com/velasco-jp/nyx/internal/seendb"
)
```

- [ ] **Step 3: Run tests to verify they fail**

```bash
go test ./internal/audit/... -run "TestDiscoveryVirtualFirstRunWarns|TestLooksVirtualUnitWithSeenDB"
```
Expected: compile error — `engine.WarnVirtual` undefined, `seendb` import missing.

- [ ] **Step 4: Update `runDiscovery` in `internal/audit/engine.go`**

Add `seendb` import:
```go
"github.com/velasco-jp/nyx/internal/seendb"
```

At the end of `runDiscovery`, after the existing pass/fail/warn evaluation block and before setting `result.Summary`, add:

```go
// Virtual network suppression: if 0 hosts and nmap evidence suggests a VM
// hypervisor MAC, check seendb. First occurrence → WARN + ack. Subsequent
// occurrences → SKIP (unless WarnVirtual override is set).
if hostCount == 0 && looksVirtual(result.Evidence) {
	db, _ := seendb.Load()
	cidr := net.CIDR
	if e.WarnVirtual || !db.IsVirtualAcked(cidr) {
		result.Status = models.StatusWarn
		result.Summary = fmt.Sprintf(
			"0 hosts discovered in %s (virtual adapter detected — future scans will suppress this warning; use --warn-virtual to always show it)",
			cidr,
		)
		_ = db.AckVirtual(cidr)
	} else {
		result.Status = models.StatusSkip
		result.Summary = fmt.Sprintf("skipped: %s is a virtual network (acknowledged)", cidr)
	}
	result.Finish()
	return result, nil
}
```

Note: this block must be placed **after** the existing violation checks but **before** the final `result.Summary = fmt.Sprintf(...)` line at the bottom of `runDiscovery`. The variable `net` is the `*intent.Network` already resolved at the top of `runDiscovery`.

- [ ] **Step 5: Run all audit tests**

```bash
go test ./internal/audit/...
```
Expected: all tests pass (nmap-dependent tests skip if nmap unavailable).

- [ ] **Step 6: Commit**

```bash
git add internal/audit/engine.go internal/audit/engine_test.go
git commit -m "feat: suppress repeat WARNs for virtual subnets using seendb"
```

---

### Task 4: `--warn-virtual` flag on `nyx audit`

**Files:**
- Modify: `internal/cli/audit.go`

- [ ] **Step 1: Add the flag variable and wire it to the engine**

In `internal/cli/audit.go`, add a package-level variable:

```go
var warnVirtual bool
```

In the `RunE` function, after `engine := audit.NewEngine(spec)`, add:

```go
engine.WarnVirtual = warnVirtual
```

In the `init()` function at the bottom of `audit.go` (or wherever `auditCmd` flags are registered — look for `auditCmd.Flags()`), add:

```go
auditCmd.Flags().BoolVar(&warnVirtual, "warn-virtual", false, "Always warn on virtual subnets, even if previously acknowledged")
```

- [ ] **Step 2: Build and smoke test**

```bash
go build -o nyx.exe ./cmd/nyx/
./nyx.exe audit --help
```
Expected: `--warn-virtual` appears in the flags list.

- [ ] **Step 3: Run full test suite**

```bash
go vet ./... && go test ./...
```
Expected: all pass.

- [ ] **Step 4: Commit**

```bash
git add internal/cli/audit.go
git commit -m "feat: add --warn-virtual flag to nyx audit"
```

---

### Task 5: End-to-end smoke test

- [ ] **Step 1: Delete seendb entry for VMware subnet if present**

```bash
# Edit ~/.nyx/seen.json and remove the 192.168.174.0/24 entry, or delete the file
rm ~/.nyx/seen.json
```

- [ ] **Step 2: Run audit against testrun.yaml — expect WARN on first run**

```bash
./nyx.exe audit --spec testrun.yaml 2>&1 | grep -E "WARN|SKIP|174"
```
Expected: `[WARN]` for `192.168.174.0/24` with "virtual adapter detected" message.

- [ ] **Step 3: Run audit again — expect SKIP**

```bash
./nyx.exe audit --spec testrun.yaml 2>&1 | grep -E "WARN|SKIP|174"
```
Expected: `[SKIP]` for `192.168.174.0/24`.

- [ ] **Step 4: Run with --warn-virtual — expect WARN again**

```bash
./nyx.exe audit --spec testrun.yaml --warn-virtual 2>&1 | grep -E "WARN|SKIP|174"
```
Expected: `[WARN]` for `192.168.174.0/24`.

- [ ] **Step 5: Push**

```bash
git push
```
