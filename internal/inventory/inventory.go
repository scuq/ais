// Package inventory loads the records a task works on (devices, products,
// versions) and reduces them to the minimum a prompt needs.
package inventory

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Record is one flat inventory row. Every value is a string; typing is the
// task's business.
type Record struct {
	Fields map[string]string `json:"fields"`
}

// Source produces records. FileSource is the v1 implementation; HTTP and SQL
// sources can implement the same interface later.
type Source interface {
	Load(ctx context.Context) ([]Record, error)
	Describe() string
}

// SourceConfig selects and configures a source.
type SourceConfig struct {
	File   string
	Format string // yaml | json | csv | mdj | auto
}

// Open returns the source for a config.
func Open(cfg SourceConfig) (Source, error) {
	if cfg.File == "" {
		return nil, fmt.Errorf("inventory: no file configured")
	}
	format := cfg.Format
	if format == "" || format == "auto" {
		switch strings.ToLower(filepath.Ext(cfg.File)) {
		case ".yaml", ".yml":
			format = "yaml"
		case ".json":
			format = "json"
		case ".csv":
			format = "csv"
		case ".mdj", ".md":
			format = "mdj"
		default:
			return nil, fmt.Errorf("inventory: cannot infer format of %s (set format: yaml|json|csv|mdj)", cfg.File)
		}
	}
	switch format {
	case "yaml", "json", "csv", "mdj":
	default:
		return nil, fmt.Errorf("inventory: unknown format %q", format)
	}
	return &FileSource{Path: cfg.File, Format: format}, nil
}

// FileSource reads a flat list of objects (yaml, json), a CSV with a
// header row, or a markdown file with one JSON block per system (mdj).
type FileSource struct {
	Path   string
	Format string
}

func (f *FileSource) Describe() string { return fmt.Sprintf("file %s (%s)", f.Path, f.Format) }

func (f *FileSource) Load(ctx context.Context) ([]Record, error) {
	fh, err := os.Open(f.Path)
	if err != nil {
		return nil, fmt.Errorf("inventory: %w", err)
	}
	defer fh.Close()
	return Parse(fh, f.Format)
}

// Parse decodes records from r in the given format.
func Parse(r io.Reader, format string) ([]Record, error) {
	switch format {
	case "csv":
		return parseCSV(r)
	case "mdj":
		return parseMDJ(r)
	case "json":
		var rows []map[string]any
		if err := json.NewDecoder(r).Decode(&rows); err != nil {
			return nil, fmt.Errorf("inventory: json: %w", err)
		}
		return fromMaps(rows), nil
	case "yaml":
		var rows []map[string]any
		if err := yaml.NewDecoder(r).Decode(&rows); err != nil && err != io.EOF {
			return nil, fmt.Errorf("inventory: yaml: %w", err)
		}
		return fromMaps(rows), nil
	}
	return nil, fmt.Errorf("inventory: unknown format %q", format)
}

func fromMaps(rows []map[string]any) []Record {
	out := make([]Record, 0, len(rows))
	for _, row := range rows {
		rec := Record{Fields: make(map[string]string, len(row))}
		for k, v := range row {
			rec.Fields[k] = stringify(v)
		}
		out = append(out, rec)
	}
	return out
}

func stringify(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case json.Number:
		return x.String()
	case float64:
		if x == float64(int64(x)) {
			return fmt.Sprintf("%d", int64(x))
		}
		return fmt.Sprintf("%g", x)
	default:
		return fmt.Sprint(x)
	}
}

func parseCSV(r io.Reader) ([]Record, error) {
	cr := csv.NewReader(r)
	cr.TrimLeadingSpace = true
	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("inventory: csv header: %w", err)
	}
	for i := range header {
		header[i] = strings.TrimSpace(header[i])
	}
	var out []Record
	for {
		row, err := cr.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("inventory: csv: %w", err)
		}
		rec := Record{Fields: make(map[string]string, len(header))}
		for i, h := range header {
			if i < len(row) {
				rec.Fields[h] = strings.TrimSpace(row[i])
			} else {
				rec.Fields[h] = ""
			}
		}
		out = append(out, rec)
	}
	return out, nil
}

// Group is one distinct tuple of the grouped fields with how many records
// share it. This is the minimized view a prompt gets: no identity, only what
// the question needs.
type Group struct {
	Fields map[string]string `json:"fields"`
	Count  int               `json:"count"`
	// Collected holds the distinct non-empty values of the collect fields
	// across the group's records (operator comments, for example).
	Collected map[string][]string `json:"collected,omitempty"`
}

// MaxCollected caps distinct values per collected field and group.
const MaxCollected = 20

// Minimize returns the distinct tuples of the given fields, sorted by their
// values in field order, with the distinct values of collect gathered per
// group. A record counts as its count field (CountField), or once.
func Minimize(recs []Record, by []string, collect []string) []Group {
	idx := map[string]int{}
	seen := map[string]map[string]map[string]bool{}
	var out []Group
	for _, r := range recs {
		key := make([]string, len(by))
		fields := make(map[string]string, len(by))
		for i, f := range by {
			key[i] = r.Fields[f]
			fields[f] = r.Fields[f]
		}
		k := strings.Join(key, "\x00")
		i, ok := idx[k]
		if !ok {
			i = len(out)
			idx[k] = i
			out = append(out, Group{Fields: fields})
			seen[k] = map[string]map[string]bool{}
		}
		out[i].Count += r.Count()
		for _, c := range collect {
			v := strings.TrimSpace(r.Fields[c])
			if v == "" {
				continue
			}
			if seen[k][c] == nil {
				seen[k][c] = map[string]bool{}
			}
			if seen[k][c][v] || len(seen[k][c]) >= MaxCollected {
				continue
			}
			seen[k][c][v] = true
			if out[i].Collected == nil {
				out[i].Collected = map[string][]string{}
			}
			out[i].Collected[c] = append(out[i].Collected[c], v)
		}
	}
	for i := range out {
		for c := range out[i].Collected {
			sort.Strings(out[i].Collected[c])
		}
	}
	sort.Slice(out, func(i, j int) bool {
		for _, f := range by {
			if a, b := out[i].Fields[f], out[j].Fields[f]; a != b {
				return a < b
			}
		}
		return false
	})
	return out
}

// Fields returns the sorted union of field names across records.
func Fields(recs []Record) []string {
	seen := map[string]bool{}
	for _, r := range recs {
		for k := range r.Fields {
			seen[k] = true
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Text limits for the free-text inventory. Loud beats silent: a file past
// them is an error, not a truncated prompt.
const (
	MaxTextLines   = 500
	MaxTextLineLen = 300
)

// LoadText reads the free-text inventory: one product per line, written by
// the operator without a device record ("Palo Alto GlobalProtect",
// "Keycloak 26.1"). Blank lines and lines that start with '#' are skipped,
// surrounding whitespace is trimmed. The lines are returned in file order.
func LoadText(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("inventory text: %w", err)
	}
	return ParseText(string(data))
}

// ParseText decodes the free-text inventory format from a string.
func ParseText(s string) ([]string, error) {
	var out []string
	for i, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if len(line) > MaxTextLineLen {
			return nil, fmt.Errorf("inventory text: line %d is longer than %d characters", i+1, MaxTextLineLen)
		}
		out = append(out, line)
		if len(out) > MaxTextLines {
			return nil, fmt.Errorf("inventory text: more than %d lines", MaxTextLines)
		}
	}
	return out, nil
}
