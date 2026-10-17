package inventory

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// mdj ("markdown json") is the inventory format for people: one level 1
// heading per system, a fenced JSON object right below it with the definitive
// values (hostname, ip, site, vendor, product, version), and level 2 headings
// with free text ("## Usage", "## Interest"). Each level 2 heading becomes a
// field named by its slug ("usage", "interest"), so the task's field policy
// decides about it like about any CSV column. Text before the first level 1
// heading is a preamble and is ignored by the records view.
//
// Anything that would be lost silently is an error instead: a system without
// a JSON block, prose between the JSON block and the first level 2 heading,
// nested JSON values, a section that repeats a JSON key.
//
// Document keeps the structure of the file, so that a tool can change one
// entry and write the file back without touching the rest.

// CountField is the reserved field that gives the number of installs an
// entry stands for ("count": 4 for four identical firewalls). It is always
// clear, and the grouping adds it instead of counting the entry once.
const CountField = "count"

// Document is a parsed mdj file.
type Document struct {
	// Preamble holds the lines before the first level 1 heading, verbatim.
	Preamble []string
	Entries  []*Entry
}

// Entry is one system or product: its heading, its JSON values and its
// free-text sections.
type Entry struct {
	Title string
	Line  int
	// Fields holds the JSON values as strings. Keys lists them in the order
	// of the file; a key that Fields has and Keys lacks renders last.
	Fields   map[string]string
	Keys     []string
	Sections []*Section
}

// Section is one level 2 heading with its text, verbatim.
type Section struct {
	Heading string
	Lines   []string
}

// ParseDocument reads an mdj file and keeps its structure.
func ParseDocument(r io.Reader) (*Document, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	doc := &Document{}
	var (
		cur       *Entry
		sec       *Section
		fence     string // open fence marker; "" outside a fence
		inJSON    bool
		jsonLine  int
		jsonLines []string
	)
	errf := func(n int, format string, args ...any) error {
		return fmt.Errorf("inventory: mdj line %d: %s", n, fmt.Sprintf(format, args...))
	}
	finish := func() error {
		if cur == nil {
			return nil
		}
		if cur.Fields == nil {
			return errf(cur.Line, "system %q has no JSON block below its heading", cur.Title)
		}
		doc.Entries = append(doc.Entries, cur)
		cur, sec = nil, nil
		return nil
	}
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimRight(sc.Text(), "\r")
		trimmed := strings.TrimSpace(line)

		if fence != "" {
			if strings.HasPrefix(trimmed, fence) && strings.Trim(trimmed, fence[:1]) == "" {
				fence = ""
				if inJSON {
					inJSON = false
					if err := cur.decodeJSON(jsonLines); err != nil {
						return nil, errf(jsonLine, "system %q: %v", cur.Title, err)
					}
					jsonLines = nil
					continue
				}
			}
			switch {
			case inJSON:
				jsonLines = append(jsonLines, line)
			case sec != nil:
				sec.Lines = append(sec.Lines, line)
			case cur == nil:
				doc.Preamble = append(doc.Preamble, line)
			}
			continue
		}

		if marker, info, ok := fenceOpen(trimmed); ok {
			fence = marker
			switch {
			case cur == nil:
				doc.Preamble = append(doc.Preamble, line)
			case sec != nil:
				sec.Lines = append(sec.Lines, line)
			case cur.Fields != nil:
				return nil, errf(n, "system %q: second code block before the first '## ' heading", cur.Title)
			case info != "" && info != "json":
				return nil, errf(n, "system %q: code block language %q (use json or none)", cur.Title, info)
			default:
				inJSON, jsonLine = true, n
			}
			continue
		}

		if title, ok := heading(line, 1); ok {
			if err := finish(); err != nil {
				return nil, err
			}
			if title == "" {
				return nil, errf(n, "empty '# ' heading")
			}
			cur = &Entry{Title: title, Line: n}
			continue
		}
		if cur == nil {
			doc.Preamble = append(doc.Preamble, line)
			continue
		}
		if title, ok := heading(line, 2); ok {
			if cur.Fields == nil {
				return nil, errf(n, "system %q: '## %s' before the JSON block", cur.Title, title)
			}
			key := slug(title)
			if key == "" {
				return nil, errf(n, "system %q: heading %q gives no field name", cur.Title, title)
			}
			if cur.Section(key) != nil {
				return nil, errf(n, "system %q: field %q is set twice", cur.Title, key)
			}
			if _, dup := cur.Fields[key]; dup {
				return nil, errf(n, "system %q: field %q is set in the JSON block and as a '## ' section", cur.Title, key)
			}
			sec = &Section{Heading: title}
			cur.Sections = append(cur.Sections, sec)
			continue
		}
		if sec == nil {
			if trimmed != "" {
				return nil, errf(n, "system %q: text outside the JSON block and outside a '## ' section", cur.Title)
			}
			continue
		}
		sec.Lines = append(sec.Lines, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("inventory: mdj: %w", err)
	}
	if fence != "" {
		return nil, errf(n, "code block is not closed")
	}
	if err := finish(); err != nil {
		return nil, err
	}
	return doc, nil
}

func parseMDJ(r io.Reader) ([]Record, error) {
	doc, err := ParseDocument(r)
	if err != nil {
		return nil, err
	}
	return doc.Records(), nil
}

// TitleField is the field that holds the heading of an entry in the
// records view, unless the JSON block sets it. A role entry has no
// hostname, so the title is what an alert can name.
const TitleField = "title"

// Records returns the flat view: the JSON values of each entry, the heading
// as TitleField, plus one field per section, named by the slug of its
// heading, with the text collapsed to single spaces.
func (d *Document) Records() []Record {
	out := make([]Record, 0, len(d.Entries))
	for _, e := range d.Entries {
		rec := Record{Fields: make(map[string]string, len(e.Fields)+len(e.Sections)+1)}
		rec.Fields[TitleField] = e.Title
		for k, v := range e.Fields {
			rec.Fields[k] = v
		}
		for _, s := range e.Sections {
			rec.Fields[slug(s.Heading)] = s.Text()
		}
		out = append(out, rec)
	}
	return out
}

// Find returns the entry with this title, compared without case and
// surrounding space, or nil.
func (d *Document) Find(title string) *Entry {
	want := strings.TrimSpace(title)
	for _, e := range d.Entries {
		if strings.EqualFold(strings.TrimSpace(e.Title), want) {
			return e
		}
	}
	return nil
}

// FindByField returns the first entry whose field has this value, compared
// without case, or nil. An empty value never matches.
func (d *Document) FindByField(key, value string) *Entry {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	for _, e := range d.Entries {
		if strings.EqualFold(strings.TrimSpace(e.Fields[key]), strings.TrimSpace(value)) {
			return e
		}
	}
	return nil
}

// Remove deletes the entry with this title and reports whether there was one.
func (d *Document) Remove(title string) bool {
	for i, e := range d.Entries {
		if strings.EqualFold(strings.TrimSpace(e.Title), strings.TrimSpace(title)) {
			d.Entries = append(d.Entries[:i], d.Entries[i+1:]...)
			return true
		}
	}
	return false
}

// Add appends a new entry with these fields, in the order given by keys.
func (d *Document) Add(title string, keys []string, fields map[string]string) *Entry {
	e := &Entry{Title: strings.TrimSpace(title), Fields: map[string]string{}}
	for _, k := range keys {
		if v, ok := fields[k]; ok {
			e.Set(k, v)
		}
	}
	for _, k := range sortedKeys(fields) {
		if _, ok := e.Fields[k]; !ok {
			e.Set(k, fields[k])
		}
	}
	d.Entries = append(d.Entries, e)
	return e
}

// Render writes the document back as mdj: the preamble, then one block per
// entry with its JSON object and its sections. Values render as JSON
// strings; the records view is the same either way.
func (d *Document) Render() []byte {
	var b strings.Builder
	if pre := trimBlank(d.Preamble); len(pre) > 0 {
		for _, l := range pre {
			b.WriteString(l + "\n")
		}
	}
	for _, e := range d.Entries {
		if b.Len() > 0 {
			b.WriteString("\n")
		}
		fmt.Fprintf(&b, "# %s\n\n```json\n%s```\n", e.Title, e.jsonBlock())
		for _, s := range e.Sections {
			fmt.Fprintf(&b, "\n## %s\n", s.Heading)
			if lines := trimBlank(s.Lines); len(lines) > 0 {
				b.WriteString("\n")
				for _, l := range lines {
					b.WriteString(l + "\n")
				}
			}
		}
	}
	return []byte(b.String())
}

// Set sets a JSON value and keeps the key order.
func (e *Entry) Set(key, value string) {
	if e.Fields == nil {
		e.Fields = map[string]string{}
	}
	if _, ok := e.Fields[key]; !ok {
		e.Keys = append(e.Keys, key)
	}
	e.Fields[key] = value
}

// Unset removes a JSON value.
func (e *Entry) Unset(key string) {
	delete(e.Fields, key)
	for i, k := range e.Keys {
		if k == key {
			e.Keys = append(e.Keys[:i], e.Keys[i+1:]...)
			return
		}
	}
}

// Section returns the section whose heading has this slug, or nil.
func (e *Entry) Section(key string) *Section {
	for _, s := range e.Sections {
		if slug(s.Heading) == key {
			return s
		}
	}
	return nil
}

// SetSection replaces the text of the section with this heading, or adds
// the section. An empty text removes the section.
func (e *Entry) SetSection(heading, text string) {
	key := slug(heading)
	for i, s := range e.Sections {
		if slug(s.Heading) == key {
			if strings.TrimSpace(text) == "" {
				e.Sections = append(e.Sections[:i], e.Sections[i+1:]...)
				return
			}
			s.Lines = strings.Split(strings.TrimSpace(text), "\n")
			return
		}
	}
	if strings.TrimSpace(text) != "" {
		e.Sections = append(e.Sections, &Section{Heading: heading, Lines: strings.Split(strings.TrimSpace(text), "\n")})
	}
}

// Text returns the section text with whitespace collapsed to single spaces.
// Code fence markers are left out; the code inside stays.
func (s *Section) Text() string {
	var parts []string
	for _, l := range s.Lines {
		if _, _, fence := fenceOpen(strings.TrimSpace(l)); fence {
			continue
		}
		parts = append(parts, l)
	}
	return strings.Join(strings.Fields(strings.Join(parts, " ")), " ")
}

// Count returns the number of installs the record stands for: its count
// field when that is a positive integer, else 1.
func (r Record) Count() int {
	var n int
	if _, err := fmt.Sscanf(strings.TrimSpace(r.Fields[CountField]), "%d", &n); err == nil && n > 0 {
		return n
	}
	return 1
}

func (e *Entry) decodeJSON(lines []string) error {
	dec := json.NewDecoder(strings.NewReader(strings.Join(lines, "\n")))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("JSON block: %w", err)
	}
	if tok != json.Delim('{') {
		return fmt.Errorf("JSON block must be an object")
	}
	fields := map[string]string{}
	var keys []string
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return fmt.Errorf("JSON block: %w", err)
		}
		key, _ := kt.(string)
		var v any
		if err := dec.Decode(&v); err != nil {
			return fmt.Errorf("JSON block: %w", err)
		}
		switch v.(type) {
		case map[string]any, []any:
			return fmt.Errorf("JSON key %q: nested values are not supported, records are flat", key)
		}
		if _, dup := fields[key]; dup {
			return fmt.Errorf("JSON key %q appears twice", key)
		}
		fields[key] = stringify(v)
		keys = append(keys, key)
	}
	if _, err := dec.Token(); err != nil {
		return fmt.Errorf("JSON block: %w", err)
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("JSON block holds more than one value")
	}
	e.Fields, e.Keys = fields, keys
	return nil
}

// jsonBlock renders the fields as an indented JSON object, keys in file
// order, then any key added later in sorted order.
func (e *Entry) jsonBlock() string {
	var keys []string
	seen := map[string]bool{}
	for _, k := range e.Keys {
		if _, ok := e.Fields[k]; ok && !seen[k] {
			keys = append(keys, k)
			seen[k] = true
		}
	}
	for _, k := range sortedKeys(e.Fields) {
		if !seen[k] {
			keys = append(keys, k)
		}
	}
	var b strings.Builder
	b.WriteString("{\n")
	for i, k := range keys {
		kb, _ := json.Marshal(k)
		vb, _ := json.Marshal(e.Fields[k])
		fmt.Fprintf(&b, "  %s: %s", kb, vb)
		if i < len(keys)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	b.WriteString("}\n")
	return b.String()
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// trimBlank drops leading and trailing blank lines.
func trimBlank(lines []string) []string {
	start, end := 0, len(lines)
	for start < end && strings.TrimSpace(lines[start]) == "" {
		start++
	}
	for end > start && strings.TrimSpace(lines[end-1]) == "" {
		end--
	}
	return lines[start:end]
}

// heading reports whether line is an ATX heading of exactly this level and
// returns its text without optional closing hashes.
func heading(line string, level int) (string, bool) {
	prefix := strings.Repeat("#", level)
	if !strings.HasPrefix(line, prefix) {
		return "", false
	}
	rest := line[level:]
	if rest != "" && rest[0] != ' ' && rest[0] != '\t' {
		return "", false // "##" for level 1, or "#tag"
	}
	rest = strings.TrimSpace(rest)
	if t := strings.TrimRight(rest, "#"); t != rest && (t == "" || strings.HasSuffix(t, " ")) {
		rest = strings.TrimSpace(t)
	}
	return rest, true
}

// fenceOpen recognizes ``` and ~~~ fences and returns the marker and the
// lowercased info string.
func fenceOpen(trimmed string) (marker, info string, ok bool) {
	for _, c := range []string{"`", "~"} {
		i := 0
		for i < len(trimmed) && trimmed[i] == c[0] {
			i++
		}
		if i >= 3 {
			return trimmed[:i], strings.ToLower(strings.TrimSpace(trimmed[i:])), true
		}
	}
	return "", "", false
}

// slug turns "Usage" into "usage" and "Owner Notes" into "owner_notes".
func slug(s string) string {
	var b bytes.Buffer
	us := false
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			us = false
		} else if !us && b.Len() > 0 {
			b.WriteByte('_')
			us = true
		}
	}
	return strings.TrimRight(b.String(), "_")
}
