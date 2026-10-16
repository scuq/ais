package inventory

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// mdj ("markdown json") is the inventory format for people: one level 1
// heading per system, a fenced JSON object right below it with the definitive
// values (hostname, ip, site, vendor, product, version), and level 2 headings
// with free text ("## Usage", "## Interest"). Each level 2 heading becomes a
// field named by its slug ("usage", "interest"), so the task's field policy
// decides about it like about any CSV column. Text before the first level 1
// heading is a preamble and is ignored.
//
// Anything that would be lost silently is an error instead: a system without
// a JSON block, prose between the JSON block and the first level 2 heading,
// nested JSON values, a section that repeats a JSON key.

type mdjRecord struct {
	title     string
	line      int
	fields    map[string]string
	hasJSON   bool
	section   string // current level 2 field; "" before the first one
	text      []string
	jsonLines []string
}

func parseMDJ(r io.Reader) ([]Record, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	var (
		out      []Record
		cur      *mdjRecord
		fence    string // open fence marker; "" outside a fence
		inJSON   bool
		jsonLine int
	)
	errf := func(n int, format string, args ...any) error {
		return fmt.Errorf("inventory: mdj line %d: %s", n, fmt.Sprintf(format, args...))
	}
	finish := func() error {
		if cur == nil {
			return nil
		}
		if !cur.hasJSON {
			return errf(cur.line, "system %q has no JSON block below its heading", cur.title)
		}
		if err := cur.endSection(); err != nil {
			return errf(cur.line, "system %q: %v", cur.title, err)
		}
		out = append(out, Record{Fields: cur.fields})
		cur = nil
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
					if err := cur.decodeJSON(); err != nil {
						return nil, errf(jsonLine, "system %q: %v", cur.title, err)
					}
				}
				continue
			}
			if inJSON {
				cur.jsonLines = append(cur.jsonLines, line)
			} else if cur != nil && cur.section != "" {
				cur.text = append(cur.text, line)
			}
			continue
		}

		if marker, info, ok := fenceOpen(trimmed); ok {
			fence = marker
			if cur == nil {
				continue // preamble
			}
			if cur.section == "" {
				if cur.hasJSON {
					return nil, errf(n, "system %q: second code block before the first '## ' heading", cur.title)
				}
				if info != "" && info != "json" {
					return nil, errf(n, "system %q: code block language %q (use json or none)", cur.title, info)
				}
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
			cur = &mdjRecord{title: title, line: n, fields: map[string]string{}}
			continue
		}
		if cur == nil {
			continue // preamble
		}
		if title, ok := heading(line, 2); ok {
			if !cur.hasJSON {
				return nil, errf(n, "system %q: '## %s' before the JSON block", cur.title, title)
			}
			if err := cur.endSection(); err != nil {
				return nil, errf(n, "system %q: %v", cur.title, err)
			}
			key := slug(title)
			if key == "" {
				return nil, errf(n, "system %q: heading %q gives no field name", cur.title, title)
			}
			if _, dup := cur.fields[key]; dup {
				return nil, errf(n, "system %q: field %q is set twice", cur.title, key)
			}
			cur.section = key
			continue
		}
		if cur.section == "" {
			if trimmed != "" {
				return nil, errf(n, "system %q: text outside the JSON block and outside a '## ' section", cur.title)
			}
			continue
		}
		cur.text = append(cur.text, line)
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
	return out, nil
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

func (m *mdjRecord) decodeJSON() error {
	dec := json.NewDecoder(strings.NewReader(strings.Join(m.jsonLines, "\n")))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		return fmt.Errorf("JSON block: %w", err)
	}
	if obj == nil {
		return fmt.Errorf("JSON block must be an object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("JSON block holds more than one value")
	}
	for k, v := range obj {
		switch v.(type) {
		case map[string]any, []any:
			return fmt.Errorf("JSON key %q: nested values are not supported, records are flat", k)
		}
		m.fields[k] = stringify(v)
	}
	m.hasJSON = true
	m.jsonLines = nil
	return nil
}

// endSection stores the text of the current section with whitespace
// collapsed to single spaces.
func (m *mdjRecord) endSection() error {
	if m.section == "" {
		return nil
	}
	if _, dup := m.fields[m.section]; dup {
		return fmt.Errorf("field %q is set in the JSON block and as a '## ' section", m.section)
	}
	m.fields[m.section] = strings.Join(strings.Fields(strings.Join(m.text, " ")), " ")
	m.section, m.text = "", nil
	return nil
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
