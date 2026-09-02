package logger

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// LogEntry is one parsed log line from the rotation set.
type LogEntry struct {
	Raw    []byte
	TS     time.Time
	Level  Level
	Msg    string
	Cmd    string
	fields map[string]string
}

// Level is one of the four log severities, ordered for filtering.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func parseLevelText(s string) Level {
	switch strings.ToLower(s) {
	case "debug":
		return LevelDebug
	case "info":
		return LevelInfo
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}

func (l Level) Text() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return "info"
	}
}

// ExportFilters narrows the exported set.
type ExportFilters struct {
	Since time.Duration // > 0: only entries newer than now-Since
	Level Level         // minimum level to include
	Cmd   string        // non-empty: only entries whose cmd or subsystem msg matches
	Last  int           // > 0: keep only the last N entries after filtering
}

// ExportOptions drives WriteArtifact. Filtering is applied to the entry
// slice before the call (FilterEntries), not inside WriteArtifact.
type ExportOptions struct {
	Format string // "json" (default) | "text"
	Scrub  bool
	Out    string // "-" or empty = stdout; otherwise a file path
}

// rawArtifactWarning is printed to stderr whenever an artifact is written
// unscrubbed, so a raw export can never silently leave the machine.
const rawArtifactWarning = "warning: --no-scrub: this artifact is NOT scrubbed and may contain private IPs, hostnames, or credentials; do not share it"

// readLogFiles returns the rotation set in chronological order (oldest
// first): the oldest rotated file first, the live file last. Only the
// rotation set is ever opened — never credentials.json, its key, or
// seen.json, no matter what else sits in the directory.
func readLogFiles(path string) []string {
	var files []string
	for i := DefaultMaxFiles; i >= 1; i-- {
		files = append(files, fmt.Sprintf("%s.%d", path, i))
	}
	files = append(files, path)
	return files
}

// ReadRotation reads every line of the rotation set in chronological
// order. Missing files are skipped (a fresh install has no rotated
// generations, and nothing runs before the first command logs); a file
// that exists but cannot be read is an error — silently dropping it would
// under-report the artifact.
func ReadRotation(path string) ([]LogEntry, error) {
	var entries []LogEntry
	for _, f := range readLogFiles(path) {
		lines, err := readLines(f)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("reading log file %q: %w", f, err)
		}
		for _, line := range lines {
			if strings.TrimSpace(string(line)) == "" {
				continue
			}
			entries = append(entries, parseLine(line))
		}
	}
	return entries, nil
}

func readLines(f string) ([][]byte, error) {
	// #nosec G304 — path is the log rotation set from NYX_LOG_FILE/DefaultPath, not user input
	file, err := os.Open(f) // nosemgrep
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var lines [][]byte
	sc := bufio.NewScanner(file)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		lines = append(lines, []byte(sc.Text()))
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

// parseLine turns one raw line into a LogEntry. Non-JSON lines keep a
// zero TS (kept, never dropped — the operator may have appended notes)
// and are treated as debug-level text so filters handle them
// conservatively.
func parseLine(raw []byte) LogEntry {
	e := LogEntry{Raw: raw, Level: LevelInfo, fields: map[string]string{}}
	trimmed := strings.TrimRight(string(raw), "\r\n")
	var obj map[string]any
	if err := json.Unmarshal([]byte(trimmed), &obj); err != nil {
		e.Level = LevelDebug
		e.Msg = trimmed
		return e
	}
	for k, v := range obj {
		if s, ok := v.(string); ok {
			e.fields[k] = s
		} else {
			e.fields[k] = fmt.Sprintf("%v", v)
		}
	}
	if ts, ok := e.fields["ts"]; ok {
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			e.TS = t
		}
	}
	e.Level = parseLevelText(e.fields["level"])
	e.Msg = e.fields["msg"]
	e.Cmd = e.fields["cmd"]
	return e
}

// FilterEntries applies the filters in order: time, level, command, last.
func FilterEntries(entries []LogEntry, f ExportFilters) []LogEntry {
	out := make([]LogEntry, 0, len(entries))
	cutoff := time.Now().Add(-f.Since)
	for i := range entries {
		if !passFilter(&entries[i], f, cutoff) {
			continue
		}
		out = append(out, entries[i])
	}
	if f.Last > 0 && len(out) > f.Last {
		out = out[len(out)-f.Last:]
	}
	return out
}

// passFilter reports whether one entry survives the filters.
func passFilter(e *LogEntry, f ExportFilters, cutoff time.Time) bool {
	if f.Since > 0 {
		// A line without a timestamp cannot prove recency.
		if e.TS.IsZero() || e.TS.Before(cutoff) {
			return false
		}
	}
	if e.Level < f.Level {
		return false
	}
	// Subsystem identity: every line carries cmd="nyx" (the OTel scope),
	// while the subsystem ("audit", "omada", ...) lives in msg. Match
	// either so `--cmd omada` keeps omada lines; unattributed lines
	// (e.g. appended notes) always pass the cmd filter.
	if f.Cmd != "" && e.Cmd != f.Cmd && e.Msg != f.Cmd {
		return false
	}
	return true
}

// WriteArtifact renders entries to opts.Out (or stdout), applying
// scrub/format per line, and appends a self-describing footer that names
// the source path actually read. With scrub disabled it passes the raw
// lines through byte-identical (plus footer) and prints the PII warning
// to stderr.
func WriteArtifact(entries []LogEntry, srcPath string, opts ExportOptions) (n int, err error) {
	var w *os.File
	if opts.Out == "" || opts.Out == "-" {
		w = os.Stdout
	} else {
		f, ferr := os.OpenFile(opts.Out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if ferr != nil {
			return 0, fmt.Errorf("opening output file %q: %w", opts.Out, ferr)
		}
		w = f
		// Only close the descriptor this call opened; the stdout path must
		// leave fd 1 intact for the rest of the process. A close failure is
		// only surfaced when no earlier error already won (a failed write
		// is the more informative of the two).
		defer func() {
			if cerr := f.Close(); cerr != nil && err == nil {
				err = fmt.Errorf("closing output file %q: %w", opts.Out, cerr)
			}
		}()
	}

	if !opts.Scrub {
		fmt.Fprintln(os.Stderr, rawArtifactWarning)
	}

	if opts.Format == "text" {
		for i := range entries {
			if opts.Scrub {
				entries[i] = scrubEntry(entries[i])
			}
			if _, err := w.WriteString(formatTextLine(&entries[i])); err != nil {
				return 0, err
			}
		}
	} else {
		for i := range entries {
			var line []byte
			if opts.Scrub {
				line = ScrubLine(entries[i].Raw)
			} else {
				line = []byte(strings.TrimRight(string(entries[i].Raw), "\n") + "\n")
			}
			if _, err := w.Write(line); err != nil {
				return 0, err
			}
		}
	}
	if err := writeFooter(w, entries, srcPath, opts); err != nil {
		return 0, err
	}
	return len(entries), nil
}

// scrubEntry returns a copy of e with PII redacted from every string
// value (msg, cmd, and each field), so the text format is scrubbed too.
// Sensitive keys are replaced wholesale; the raw line is left untouched
// because only the parsed fields are rendered.
func scrubEntry(e LogEntry) LogEntry {
	out := e
	out.Msg = defaultReplacer.scrubText(e.Msg)
	out.Cmd = defaultReplacer.scrubText(e.Cmd)
	if out.fields == nil {
		return out
	}
	f := make(map[string]string, len(e.fields))
	for k, v := range e.fields {
		if scrubKeyRe.MatchString(k) {
			f[k] = redactValue
			continue
		}
		f[k] = defaultReplacer.scrubText(v)
	}
	out.fields = f
	return out
}

// formatTextLine renders one human-readable line: "ts LEVEL [cmd] msg
// k=v k=v", sorted by key for stable output.
func formatTextLine(e *LogEntry) string {
	var b strings.Builder
	if !e.TS.IsZero() {
		b.WriteString(e.TS.UTC().Format("2006-01-02T15:04:05.000Z"))
		b.WriteByte(' ')
	}
	b.WriteString(strings.ToUpper(e.Level.Text()))
	fmt.Fprintf(&b, " [%s] %s", e.Cmd, e.Msg)
	keys := make([]string, 0, len(e.fields))
	for k := range e.fields {
		switch k {
		case "ts", "level", "msg", "cmd":
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, " %s=%s", k, e.fields[k])
	}
	b.WriteByte('\n')
	return b.String()
}

// writeFooter appends the self-describing artifact footer: line count,
// source coverage, scrub mode, and the time range.
func writeFooter(w *os.File, entries []LogEntry, srcPath string, opts ExportOptions) error {
	var start, end time.Time
	for i := range entries {
		if entries[i].TS.IsZero() {
			continue
		}
		if start.IsZero() || entries[i].TS.Before(start) {
			start = entries[i].TS
		}
		if end.IsZero() || entries[i].TS.After(end) {
			end = entries[i].TS
		}
	}
	mode := "scrubbed"
	if !opts.Scrub {
		mode = "raw (UNSAFE)"
	}
	src := readLogFiles(srcPath)
	present := 0
	for _, f := range src {
		if _, err := os.Stat(f); err == nil {
			present++
		}
	}
	var b strings.Builder
	fmt.Fprintf(&b, "# lines=%d sources=%d/%d scrub=%s ", len(entries), present, len(src), mode)
	if start.IsZero() {
		b.WriteString("range=none")
	} else {
		fmt.Fprintf(&b, "range=%s..%s",
			start.UTC().Format(time.RFC3339),
			end.UTC().Format(time.RFC3339))
	}
	b.WriteByte('\n')
	_, err := w.WriteString(b.String())
	return err
}

// ParseLevelFlag maps the --level flag value to a minimum level.
func ParseLevelFlag(s string) (Level, error) {
	switch strings.ToLower(s) {
	case "debug":
		return LevelDebug, nil
	case "info":
		return LevelInfo, nil
	case "warn":
		return LevelWarn, nil
	case "error":
		return LevelError, nil
	default:
		return LevelDebug, fmt.Errorf("invalid --level %q: expected debug, info, warn, or error", s)
	}
}
