package logger

import (
	"bytes"
	"io"
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
	if err := os.WriteFile(path, []byte(content), 0600); err != nil { // nosemgrep: go_filesystem_rule-fileread — path built under t.TempDir()
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

// TestReadRotationGenerationNaming pins the rotation file naming:
// generation i lives at <path>.i (dot separator), so test helpers that
// build the names cannot drift from readLogFiles.
func TestReadRotationGenerationNaming(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nyx.log")
	writeFile(t, path+".1", exportLineA+"\n")
	writeFile(t, path, exportLineC+"\n")

	entries, err := ReadRotation(path)
	if err != nil {
		t.Fatalf("ReadRotation: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2 (generation .1 must be picked up)", len(entries))
	}
	if got := entries[0].Msg; got != "audit" {
		t.Errorf("entry[0].msg = %q, want audit (from .1)", got)
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

// TestFilterEntriesCmdKeepsUnattributedLines pins the documented behavior:
// unparseable lines (appended operator notes) carry no cmd field and must
// survive the cmd filter — ReadRotation keeps them, and a --cmd export
// must not silently drop the notes it is asked to export.
func TestFilterEntriesCmdKeepsUnattributedLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nyx.log")
	writeFile(t, path, "operator note: manual entry\n"+exportLineA+"\n"+exportLineB+"\n")
	entries, err := ReadRotation(path)
	if err != nil {
		t.Fatalf("ReadRotation: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("got %d entries, want 3 (note + 2 attributed)", len(entries))
	}
	got := FilterEntries(entries, ExportFilters{Cmd: "omada"})
	var msgs []string
	for i := range got {
		msgs = append(msgs, got[i].Msg)
	}
	if len(msgs) != 2 {
		t.Fatalf("cmd=omada got %v, want the note plus the omada line", msgs)
	}
	for i := range msgs {
		if msgs[i] == "omada" {
			continue
		}
		if !strings.Contains(msgs[i], "operator note") {
			t.Fatalf("cmd=omada kept %v, want the unattributed note to pass", msgs)
		}
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
	b, err := os.ReadFile(out) // nosemgrep: go_filesystem_rule-fileread — artifact path built under t.TempDir()
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
	rb, err := os.ReadFile(outRaw) // nosemgrep: go_filesystem_rule-fileread — raw artifact path built under t.TempDir()
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
	tb, err := os.ReadFile(outText) // nosemgrep: go_filesystem_rule-fileread — text artifact path built under t.TempDir()
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
	b, _ := os.ReadFile(out) // nosemgrep: go_filesystem_rule-fileread — artifact path built under t.TempDir()
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

// TestParseLevelTextAndText round-trips every level through both the
// parser (including the "warning" alias and the default) and the Text
// renderer (including the default case).
func TestParseLevelTextAndText(t *testing.T) {
	parses := map[string]Level{"debug": LevelDebug, "info": LevelInfo, "warn": LevelWarn, "warning": LevelWarn, "error": LevelError, "chatty": LevelInfo}
	for in, want := range parses {
		if got := parseLevelText(in); got != want {
			t.Errorf("parseLevelText(%q) = %s, want %s", in, got.Text(), want.Text())
		}
	}
	texts := map[Level]string{LevelDebug: "debug", LevelInfo: "info", LevelWarn: "warn", LevelError: "error", Level(99): "info"}
	for lvl, want := range texts {
		if got := lvl.Text(); got != want {
			t.Errorf("Level(%d).Text() = %q, want %q", int(lvl), got, want)
		}
	}
}

// TestReadRotationUnreadableFile: a path that exists but cannot be read as
// a file is an error (silently dropping it would under-report the
// artifact). On every platform, placing a directory at the log path makes
// os.Open succeed but the scanner fail with "is a directory", exercising
// the readLines sc.Err() and ReadRotation error-wrap paths portably.
func TestReadRotationUnreadableFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nyx.log")
	if err := os.Mkdir(path, 0700); err != nil { // nosemgrep: go.lang.correctness.permissions.file_permission.incorrect-default-permission — dir needs execute to be a directory
		t.Fatalf("making directory at log path: %v", err)
	}

	if _, err := ReadRotation(path); err == nil {
		t.Fatal("expected an error for an unreadable log file, got nil")
	}
}

// TestReadRotationSkipsBlankLines: blank and whitespace-only lines are
// dropped, real lines are kept.
func TestReadRotationSkipsBlankLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nyx.log")
	writeFile(t, path, "\n   \n"+exportLineA+"\n\n")
	entries, err := ReadRotation(path)
	if err != nil {
		t.Fatalf("ReadRotation: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1 (blank lines dropped)", len(entries))
	}
}

// TestParseLineVariants: a JSON line with a bad ts and a non-string value
// still parses (ts stays zero, the value is stringified).
func TestParseLineVariants(t *testing.T) {
	e := parseLine([]byte(`{"ts":"not-a-time","level":"warn","msg":"m","cmd":"nyx","count":42,"flag":true}`))
	if !e.TS.IsZero() {
		t.Errorf("bad ts must stay zero, got %v", e.TS)
	}
	if e.Level != LevelWarn || e.Msg != "m" || e.Cmd != "nyx" {
		t.Errorf("parsed = level %s msg %q cmd %q", e.Level.Text(), e.Msg, e.Cmd)
	}
	if e.fields["count"] != "42" || e.fields["flag"] != "true" {
		t.Errorf("non-string values must be stringified, got %q %q", e.fields["count"], e.fields["flag"])
	}
	// A JSON line with no ts at all also parses with a zero TS.
	e2 := parseLine([]byte(`{"level":"info"}`))
	if !e2.TS.IsZero() || e2.Level != LevelInfo {
		t.Errorf("no-ts line = ts %v level %s, want zero/info", e2.TS, e2.Level.Text())
	}
}

// TestParseLineLargeInteger pins the text-format path: a large integer
// field is stringified exactly (json.Number), not as float64 scientific
// notation.
func TestParseLineLargeInteger(t *testing.T) {
	e := parseLine([]byte(`{"level":"info","msg":"m","count_ns":1735689600000000000}`))
	if e.fields["count_ns"] != "1735689600000000000" {
		t.Errorf("large integer = %q, want exact value", e.fields["count_ns"])
	}
}

// TestParseLevelFlag verifies the --level flag mapping: the four valid
// values and the default-case error (unparseable values are errors, never
// silent fallbacks).
func TestParseLevelFlag(t *testing.T) {
	cases := []struct {
		in   string
		want Level
		err  bool
	}{
		{"debug", LevelDebug, false},
		{"info", LevelInfo, false},
		{"warn", LevelWarn, false},
		{"error", LevelError, false},
		{"WARN", LevelWarn, false}, // case-insensitive
		{"chatty", LevelDebug, true},
		{"", LevelDebug, true},
	}
	for _, c := range cases {
		got, err := ParseLevelFlag(c.in)
		if c.err {
			if err == nil {
				t.Errorf("ParseLevelFlag(%q) = %v, want error", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseLevelFlag(%q) error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseLevelFlag(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// TestWriteArtifactOpenError: an output path that cannot be created
// surfaces the open error, not a silent success.
func TestWriteArtifactOpenError(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "no-such-dir", "artifact.log")
	entries := []LogEntry{{Raw: []byte(exportLineA)}}
	if _, err := WriteArtifact(entries, filepath.Join(dir, "nyx.log"), ExportOptions{Out: out}); err == nil {
		t.Fatal("expected an open error for a bad output path, got nil")
	}
}

// TestWriteArtifactFooterVariants covers the footer branches the main test
// does not: range=none (no timestamped entries) and the zero-TS entries
// case.
func TestWriteArtifactFooterVariants(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "nyx.log")
	out := filepath.Join(dir, "artifact.log")

	// No timestamped entries at all (raw text line): range=none.
	entries := []LogEntry{{Raw: []byte("operator note")}}
	if _, err := WriteArtifact(entries, src, ExportOptions{Scrub: true, Out: out}); err != nil {
		t.Fatalf("WriteArtifact: %v", err)
	}
	b, err := os.ReadFile(out) // nosemgrep: go_filesystem_rule-fileread — artifact path built under t.TempDir()
	if err != nil {
		t.Fatalf("reading artifact: %v", err)
	}
	if !strings.Contains(string(b), "# lines=1 sources=0/4 scrub=scrubbed range=none") {
		t.Errorf("footer missing range=none:\n%s", b)
	}
}

// TestWriteArtifactTextNoFields: an entry with nil fields renders the text
// line without a fields loop (the scrubEntry nil-fields guard).
func TestWriteArtifactTextNoFields(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "nyx.log")
	out := filepath.Join(dir, "text.log")
	entries := []LogEntry{
		{Raw: []byte("note"), Level: LevelInfo, Msg: "bare note", Cmd: "nyx"},
	}
	if _, err := WriteArtifact(entries, src, ExportOptions{Format: "text", Scrub: true, Out: out}); err != nil {
		t.Fatalf("WriteArtifact text: %v", err)
	}
	b, err := os.ReadFile(out) // nosemgrep: go_filesystem_rule-fileread — artifact path built under t.TempDir()
	if err != nil {
		t.Fatalf("reading artifact: %v", err)
	}
	if !strings.Contains(string(b), "INFO [nyx] bare note") {
		t.Errorf("text artifact missing entry:\n%s", b)
	}
}

// TestWriteArtifactTextScrubSensitiveKey: a field under a sensitive key
// (matched by scrubKeyRe) is replaced wholesale even in the text format,
// and its value never leaks into the rendered line.
func TestWriteArtifactTextScrubSensitiveKey(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "nyx.log")
	out := filepath.Join(dir, "text.log")
	in := `{"ts":"2026-09-01T09:00:00.000Z","level":"info","msg":"omada","cmd":"nyx","api_key":"abc","note":"ok"}`
	e := parseLine([]byte(in))
	if _, err := WriteArtifact([]LogEntry{e}, src, ExportOptions{Format: "text", Scrub: true, Out: out}); err != nil {
		t.Fatalf("WriteArtifact text: %v", err)
	}
	b, err := os.ReadFile(out) // nosemgrep: go_filesystem_rule-fileread — artifact path built under t.TempDir()
	if err != nil {
		t.Fatalf("reading artifact: %v", err)
	}
	s := string(b)
	if strings.Contains(s, "abc") || !strings.Contains(s, "api_key=[redacted]") || !strings.Contains(s, "note=ok") {
		t.Errorf("sensitive key must be redacted in text artifact, got:\n%s", s)
	}
}

// TestWriteArtifactFooterSourcesPresent: when the source log actually
// exists on disk, the footer's sources=N/4 reflects the count of present
// rotation files.
func TestWriteArtifactFooterSourcesPresent(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "nyx.log")
	writeFile(t, src, exportLineA+"\n")
	out := filepath.Join(dir, "artifact.log")
	entries, err := ReadRotation(src)
	if err != nil {
		t.Fatalf("ReadRotation: %v", err)
	}
	if _, err := WriteArtifact(entries, src, ExportOptions{Scrub: true, Out: out}); err != nil {
		t.Fatalf("WriteArtifact: %v", err)
	}
	b, err := os.ReadFile(out) // nosemgrep: go_filesystem_rule-fileread — artifact path built under t.TempDir()
	if err != nil {
		t.Fatalf("reading artifact: %v", err)
	}
	if !strings.Contains(string(b), "# lines=1 sources=1/4 scrub=scrubbed") {
		t.Errorf("footer must report the live file present, got:\n%s", b)
	}
}

// TestWriteArtifactDoesNotMutateEntries: the scrubbed text path must not
// write back into the caller's slice — a second export (e.g. a JSON
// artifact from the same slice) must still see the original, unscrubbed
// values.
func TestWriteArtifactDoesNotMutateEntries(t *testing.T) {
	in := `{"ts":"2026-09-01T09:00:00.000Z","level":"info","msg":"audit","cmd":"nyx","target":"192.168.5.4"}`
	entries := []LogEntry{{Raw: []byte(in), TS: mustParseTime(t, "2026-09-01T09:00:00Z"), Level: LevelInfo, Msg: "audit", Cmd: "nyx"}}
	src := filepath.Join(t.TempDir(), "nyx.log")
	outText := filepath.Join(t.TempDir(), "text.log")
	if _, err := WriteArtifact(entries, src, ExportOptions{Format: "text", Scrub: true, Out: outText}); err != nil {
		t.Fatalf("WriteArtifact text: %v", err)
	}
	if !strings.Contains(string(entries[0].Raw), "192.168.5.4") {
		t.Fatalf("caller's slice was mutated by the text path:\n%v", entries)
	}
	outJSON := filepath.Join(t.TempDir(), "json.log")
	if _, err := WriteArtifact(entries, src, ExportOptions{Format: "json", Scrub: true, Out: outJSON}); err != nil {
		t.Fatalf("WriteArtifact json: %v", err)
	}
	jb, _ := os.ReadFile(outJSON) // nosemgrep: go_filesystem_rule-fileread — artifact path built under t.TempDir()
	if !strings.Contains(string(jb), "[ip]") {
		t.Errorf("second export must still scrub (original value present), got:\n%s", jb)
	}
}

// TestWriteArtifactStdout: Out "-" writes to the real stdout; capture it
// to prove the stdout branch (and the raw stderr warning) work.
func TestWriteArtifactStdout(t *testing.T) {
	old := os.Stdout
	defer func() { os.Stdout = old }()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout = w
	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(&buf, r)
		done <- struct{}{}
	}()

	src := filepath.Join(t.TempDir(), "nyx.log")
	entries := []LogEntry{{Raw: []byte(exportLineA)}}
	if _, err := WriteArtifact(entries, src, ExportOptions{}); err != nil {
		t.Fatalf("WriteArtifact stdout: %v", err)
	}
	_ = w.Close()
	os.Stdout = old
	<-done // wait for the copy to finish before reading buf (race)

	s := buf.String()
	if !strings.Contains(s, "msg") || !strings.Contains(s, "# lines=1") {
		t.Errorf("stdout artifact incomplete:\n%s", s)
	}
}
