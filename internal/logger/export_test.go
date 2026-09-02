package logger

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	exportLineA = `{"ts":"2026-09-01T07:00:00.000Z","level":"info","msg":"audit","cmd":"nyx","version":"v0.4.0"}`
	exportLineB = `{"ts":"2026-09-01T08:30:00.000Z","level":"warn","msg":"omada","cmd":"nyx","event":"retry","attempt":2,"error":"session expired"}`
	exportLineC = `{"ts":"2026-09-01T09:00:00.000Z","level":"error","msg":"audit","cmd":"nyx","status":"fail"}`
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// TestReadRotationChronologicalOrder verifies the rotation set is read
// oldest first (oldest rotated generation first, live file last) and that
// missing generations are skipped, not errors.
func TestReadRotationChronologicalOrder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nyx.log")
	// Oldest first on disk: .3 holds A, .1 holds B, live holds C.
	writeFile(t, path+".3", exportLineA+"\n")
	writeFile(t, path+".1", exportLineB+"\n")
	writeFile(t, path, exportLineC+"\n")
	// .2 intentionally absent.

	entries, err := ReadRotation(path)
	if err != nil {
		t.Fatalf("ReadRotation: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3", len(entries))
	}
	if got := entries[0].Msg; got != "audit" {
		t.Errorf("entry[0].msg = %q, want audit (from .3)", got)
	}
	if got := entries[1].Msg; got != "omada" {
		t.Errorf("entry[1].msg = %q, want omada (from .1)", got)
	}
	if got := entries[2].Msg; got != "audit" {
		t.Errorf("entry[2].msg = %q, want audit (live file)", got)
	}
}

// TestReadRotationEmptyOnMissingFiles: a fresh install has no log files at
// all — the read must return zero entries, not an error.
func TestReadRotationEmptyOnMissingFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does-not-exist.log")
	entries, err := ReadRotation(path)
	if err != nil {
		t.Fatalf("ReadRotation on missing files: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("got %d entries, want 0", len(entries))
	}
}

// TestReadRotationKeepsUnparseableLines: non-JSON lines (appended notes)
// must survive as debug-level text entries, never dropped.
func TestReadRotationKeepsUnparseableLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nyx.log")
	writeFile(t, path, "operator note: nothing logged here\n"+exportLineA+"\n")

	entries, err := ReadRotation(path)
	if err != nil {
		t.Fatalf("ReadRotation: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if entries[0].Level != LevelDebug || !entries[0].TS.IsZero() {
		t.Errorf("unparseable line = level %s ts %v, want debug/zero", entries[0].Level.Text(), entries[0].TS)
	}
	if entries[0].Msg != "operator note: nothing logged here" {
		t.Errorf("unparseable line msg = %q", entries[0].Msg)
	}
}

func TestFilterEntries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nyx.log")
	writeFile(t, path, exportLineA+"\n"+exportLineB+"\n"+exportLineC+"\n")
	entries, err := ReadRotation(path)
	if err != nil {
		t.Fatalf("ReadRotation: %v", err)
	}

	cases := []struct {
		name    string
		f       ExportFilters
		wantMsg []string
	}{
		{"no filter", ExportFilters{}, []string{"audit", "omada", "audit"}},
		{"level info drops debug but keeps all", ExportFilters{Level: LevelInfo}, []string{"audit", "omada", "audit"}},
		{"level warn drops info lines", ExportFilters{Level: LevelWarn}, []string{"omada", "audit"}},
		{"level error keeps only errors", ExportFilters{Level: LevelError}, []string{"audit"}},
		{"cmd matches subsystem in msg", ExportFilters{Cmd: "omada"}, []string{"omada"}},
		{"cmd matches command", ExportFilters{Cmd: "nyx"}, []string{"audit", "omada", "audit"}},
		{"cmd unknown drops all attributed", ExportFilters{Cmd: "batfish"}, nil},
		{"last caps to tail", ExportFilters{Last: 2}, []string{"omada", "audit"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := FilterEntries(entries, c.f)
			var gotMsg []string
			for i := range got {
				gotMsg = append(gotMsg, got[i].Msg)
			}
			if len(gotMsg) != len(c.wantMsg) {
				t.Fatalf("got msgs %v, want %v", gotMsg, c.wantMsg)
			}
			for i := range gotMsg {
				if gotMsg[i] != c.wantMsg[i] {
					t.Fatalf("got msgs %v, want %v", gotMsg, c.wantMsg)
				}
			}
		})
	}
}

// TestFilterEntriesSince verifies the time filter keeps recent entries and
// drops old ones; the cutoff is wall-clock relative, so use fixed ages.
func TestFilterEntriesSince(t *testing.T) {
	now := time.Now()
	entries := []LogEntry{
		{Raw: []byte("old"), TS: now.Add(-3 * time.Hour), Level: LevelInfo, Msg: "old"},
		{Raw: []byte("new"), TS: now.Add(-5 * time.Minute), Level: LevelInfo, Msg: "new"},
		{Raw: []byte("note"), TS: time.Time{}, Level: LevelDebug, Msg: "note"}, // no ts
	}
	got := FilterEntries(entries, ExportFilters{Since: time.Hour})
	if len(got) != 1 || got[0].Msg != "new" {
		t.Errorf("since=1h got %d entries, want only 'new'", len(got))
	}
	// Since=0 disables the time filter entirely.
	gotAll := FilterEntries(entries, ExportFilters{})
	if len(gotAll) != 3 {
		t.Errorf("no filter got %d entries, want 3", len(gotAll))
	}
}

func TestWriteArtifact(t *testing.T) {
	entries := []LogEntry{
		{Raw: []byte(exportLineB), TS: mustParseTime(t, "2026-09-01T08:30:00Z"), Level: LevelWarn, Msg: "omada", Cmd: "nyx",
			fields: map[string]string{"ts": "2026-09-01T08:30:00.000Z", "level": "warn", "msg": "omada", "cmd": "nyx", "event": "retry", "attempt": "2", "error": "session expired"}},
		{Raw: []byte(exportLineA), TS: mustParseTime(t, "2026-09-01T07:00:00Z"), Level: LevelInfo, Msg: "audit", Cmd: "nyx",
			fields: map[string]string{"ts": "2026-09-01T07:00:00.000Z", "level": "info", "msg": "audit", "cmd": "nyx"}},
	}
	src := filepath.Join(t.TempDir(), "nyx.log")
	out := filepath.Join(t.TempDir(), "artifact.log")

	// Scrubbed JSON artifact: PII redacted, footer self-describing.
	n, err := WriteArtifact(entries, src, ExportOptions{Format: "json", Scrub: true, Out: out})
	if err != nil {
		t.Fatalf("WriteArtifact scrubbed: %v", err)
	}
	if n != 2 {
		t.Errorf("WriteArtifact returned %d, want 2", n)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading artifact: %v", err)
	}
	s := string(b)
	if !strings.Contains(s, `"attempt":2,"cmd":"nyx","error":"session expired","event":"retry","level":"warn","msg":"omada"`) {
		t.Errorf("scrubbed artifact missing scrubbed omada line:\n%s", s)
	}
	if !strings.Contains(s, "# lines=2 sources=0/4 scrub=scrubbed") {
		t.Errorf("footer missing/incorrect:\n%s", s)
	}
	if !strings.Contains(s, "range=2026-09-01T07:00:00Z..2026-09-01T08:30:00Z") {
		t.Errorf("footer range missing/incorrect:\n%s", s)
	}

	// Raw artifact: byte-identical lines + raw (UNSAFE) footer.
	outRaw := filepath.Join(t.TempDir(), "raw.log")
	if _, err := WriteArtifact(entries, src, ExportOptions{Format: "json", Scrub: false, Out: outRaw}); err != nil {
		t.Fatalf("WriteArtifact raw: %v", err)
	}
	rb, err := os.ReadFile(outRaw)
	if err != nil {
		t.Fatalf("reading raw artifact: %v", err)
	}
	rs := string(rb)
	if !strings.Contains(rs, exportLineA+"\n") || !strings.Contains(rs, exportLineB+"\n") {
		t.Errorf("raw artifact must be byte-identical:\n%s", rs)
	}
	if !strings.Contains(rs, "scrub=raw (UNSAFE)") {
		t.Errorf("raw footer missing 'raw (UNSAFE)':\n%s", rs)
	}

	// Text artifact: one human line per entry, sorted keys, scrubbed.
	outText := filepath.Join(t.TempDir(), "text.log")
	if _, err := WriteArtifact(entries, src, ExportOptions{Format: "text", Scrub: true, Out: outText}); err != nil {
		t.Fatalf("WriteArtifact text: %v", err)
	}
	tb, err := os.ReadFile(outText)
	if err != nil {
		t.Fatalf("reading text artifact: %v", err)
	}
	ts := string(tb)
	if !strings.Contains(ts, "2026-09-01T08:30:00.000Z WARN [nyx] omada attempt=2 error=session expired event=retry") {
		t.Errorf("text artifact missing/incorrect scrubbed omada line:\n%s", ts)
	}
	if !strings.Contains(ts, "2026-09-01T07:00:00.000Z INFO [nyx] audit") {
		t.Errorf("text artifact missing scrubbed audit line:\n%s", ts)
	}
}

// TestWriteArtifactScrubRedactsPII verifies the scrub path actually
// redacts a PII-bearing line end to end (not just the shape of the output).
func TestWriteArtifactScrubRedactsPII(t *testing.T) {
	in := `{"ts":"2026-09-01T09:00:00.000Z","level":"warn","msg":"omada","cmd":"nyx","event":"relogin","error":"controller at 192.168.5.4 refused"}`
	entries := []LogEntry{{Raw: []byte(in)}}
	out := filepath.Join(t.TempDir(), "pi.log")
	if _, err := WriteArtifact(entries, filepath.Join(t.TempDir(), "nyx.log"), ExportOptions{Scrub: true, Out: out}); err != nil {
		t.Fatalf("WriteArtifact: %v", err)
	}
	b, _ := os.ReadFile(out)
	s := string(b)
	if strings.Contains(s, "192.168.5.4") {
		t.Errorf("PII IP must be redacted, got:\n%s", s)
	}
	if !strings.Contains(s, "[ip]") {
		t.Errorf("expected [ip] placeholder, got:\n%s", s)
	}
}

func mustParseTime(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		t.Fatalf("parsing %q: %v", s, err)
	}
	return ts
}
