// Package pseudo keeps sensitive inventory values out of the model's context.
//
// Three tiers, cheapest first. Minimization: a task exposes only the columns
// it needs (internal/inventory.Minimize). Tokenization: a value that must be
// referenced is replaced by a stable per-task token and mapped back on the
// host after the run. Defence in depth: a redactor scrubs tool outputs inside
// the container and a leak check scans the raw model output on the host.
package pseudo

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/scuq/ais/internal/inventory"
)

// Mode is what happens to one inventory field.
type Mode string

const (
	// Clear passes the value through unchanged.
	Clear Mode = "clear"
	// Pseudonym replaces the value with a token.
	Pseudonym Mode = "pseudonym"
	// Drop removes the field entirely.
	Drop Mode = "drop"
	// Scrub passes free text (a comment) through the redaction policy:
	// hostnames, addresses and literals inside it are rewritten, the rest
	// stays. For operator notes that are useful context but may name hosts.
	Scrub Mode = "scrub"
)

// ParseMode validates a mode string.
func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case Clear, Pseudonym, Drop, Scrub:
		return Mode(s), nil
	}
	return "", fmt.Errorf("unknown field mode %q (use: clear, pseudonym, scrub, drop)", s)
}

// Policy maps field names to modes. A field not in the policy is dropped:
// the policy fails closed.
type Policy map[string]Mode

// ModeOf returns the mode for a field, Drop when unlisted.
func (p Policy) ModeOf(field string) Mode {
	if m, ok := p[field]; ok {
		return m
	}
	return Drop
}

// ClearFields returns the fields the policy passes through, sorted.
func (p Policy) ClearFields() []string {
	var out []string
	for f, m := range p {
		if m == Clear {
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}

// SaltSize is the per-task salt length in bytes.
const SaltSize = 32

// NewSalt returns a random per-task salt.
func NewSalt() ([]byte, error) {
	b := make([]byte, SaltSize)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// Map is the token → real value mapping of one task. It lives on the host
// only; nothing that reaches the container may contain it.
type Map struct {
	Task   string
	SaltID string
	Tokens map[string]string // token → real value
	fields map[string]string // token → field name
}

// NewMap returns an empty map.
func NewMap(task, saltID string) *Map {
	return &Map{Task: task, SaltID: saltID, Tokens: map[string]string{}, fields: map[string]string{}}
}

// Add records one token. Field is kept so a map can be audited.
func (m *Map) Add(token, field, value string) {
	m.Tokens[token] = value
	m.fields[token] = field
}

// Field returns the inventory field a token was derived from.
func (m *Map) Field(token string) string { return m.fields[token] }

// Values returns every real value in the map, deduplicated.
func (m *Map) Values() []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range m.Tokens {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// Tokenizer derives stable tokens. The same salt, field and value always give
// the same token, which is what lets a later run refer to the same device
// and lets results_recent deduplicate across runs. Different tasks have
// different salts, so tokens never correlate across tasks.
type Tokenizer struct {
	salt   []byte
	labels map[string]string // field → token label
	// HostnameMode and IPMode select rot13 / cgnat forms for fields
	// labelled host and ip; empty means opaque tokens.
	HostnameMode string
	IPMode       string
}

// NewTokenizer returns a tokenizer. labels maps field names to the short
// prefix used in tokens (hostname → "host"); unlisted fields use the field
// name itself.
func NewTokenizer(salt []byte, labels map[string]string) *Tokenizer {
	if labels == nil {
		labels = map[string]string{}
	}
	return &Tokenizer{salt: salt, labels: labels}
}

// DefaultLabels are the token prefixes for common inventory fields.
var DefaultLabels = map[string]string{
	"hostname": "host",
	"host":     "host",
	"fqdn":     "host",
	"ip":       "ip",
	"ipv4":     "ip",
	"ipv6":     "ip",
	"address":  "ip",
	"site":     "site",
	"owner":    "owner",
	"user":     "user",
	"email":    "mail",
}

const tokenHexLen = 8

func (t *Tokenizer) label(field string) string {
	if l, ok := t.labels[field]; ok {
		return l
	}
	if l, ok := DefaultLabels[strings.ToLower(field)]; ok {
		return l
	}
	l := strings.ToLower(field)
	l = tokenLabelClean.ReplaceAllString(l, "")
	if l == "" {
		l = "val"
	}
	return l
}

var tokenLabelClean = regexp.MustCompile(`[^a-z]`)

// Token returns the token for a field value, registering it in m. On a
// collision with a different value the token is lengthened deterministically.
func (t *Tokenizer) Token(m *Map, field, value string) string {
	label := t.label(field)
	switch {
	case label == "host" && t.HostnameMode == HostnameRot13:
		tok := Rot13(value)
		if tok != value {
			m.Add(tok, field, value)
			return tok
		}
	case label == "ip" && t.IPMode == IPCGNAT:
		if ip := net.ParseIP(value); ip != nil {
			if tok := CGNATAddress(t.salt, ip); tok != "" {
				m.Add(tok, field, value)
				return tok
			}
		}
	}
	mac := hmac.New(sha256.New, t.salt)
	mac.Write([]byte(field))
	mac.Write([]byte{0})
	mac.Write([]byte(value))
	full := hex.EncodeToString(mac.Sum(nil))
	for n := tokenHexLen; n <= len(full); n += 4 {
		tok := label + "-" + full[:n]
		if prev, ok := m.Tokens[tok]; !ok || prev == value {
			m.Add(tok, field, value)
			return tok
		}
	}
	// 64 hex characters of HMAC cannot collide in practice; this is a guard.
	tok := label + "-" + full
	m.Add(tok, field, value)
	return tok
}

// Apply returns a pseudonymized copy of the records according to the policy,
// filling m with the tokens it minted. Dropped fields are absent from the
// result. Empty values are left empty rather than tokenized. Scrub fields go
// through rd; a nil rd drops them (fail closed).
func Apply(p Policy, t *Tokenizer, m *Map, rd *Redactor, recs []inventory.Record) []inventory.Record {
	out := make([]inventory.Record, 0, len(recs))
	for _, r := range recs {
		nr := inventory.Record{Fields: map[string]string{}}
		for f, v := range r.Fields {
			switch p.ModeOf(f) {
			case Clear:
				nr.Fields[f] = v
			case Pseudonym:
				if v == "" {
					nr.Fields[f] = ""
				} else {
					nr.Fields[f] = t.Token(m, f, v)
				}
			case Scrub:
				if rd != nil {
					nr.Fields[f] = rd.Redact(v)
				}
			default:
				// The install count of an entry is a number, never an
				// identity; it stays so that the grouping can add it.
				if f == inventory.CountField {
					nr.Fields[f] = v
				}
			}
		}
		out = append(out, nr)
	}
	return out
}

// matcher builds one regexp over every token in the map, longest first so
// "sj01.ploreqlar.flfgrzf" wins over "sj01", with word boundaries so a
// token never matches inside a longer word.
func (m *Map) matcher() *regexp.Regexp {
	if len(m.Tokens) == 0 {
		return nil
	}
	toks := make([]string, 0, len(m.Tokens))
	for t := range m.Tokens {
		toks = append(toks, t)
	}
	sort.Slice(toks, func(i, j int) bool {
		if len(toks[i]) != len(toks[j]) {
			return len(toks[i]) > len(toks[j])
		}
		return toks[i] < toks[j]
	})
	quoted := make([]string, len(toks))
	for i, t := range toks {
		quoted[i] = regexp.QuoteMeta(t)
	}
	return regexp.MustCompile(`(?i)\b(?:` + strings.Join(quoted, "|") + `)\b`)
}

// Depseudonymize walks a decoded JSON document and replaces tokens found in
// m with their real values, both as whole strings and embedded in prose.
// Maps and slices are copied; other values are returned as is.
func Depseudonymize(doc any, m *Map) any {
	switch v := doc.(type) {
	case string:
		return m.Replace(v)
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, val := range v {
			out[k] = Depseudonymize(val, m)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, val := range v {
			out[i] = Depseudonymize(val, m)
		}
		return out
	}
	return doc
}

// Replace substitutes every known token in s.
func (m *Map) Replace(s string) string {
	re := m.matcher()
	if re == nil {
		return s
	}
	return re.ReplaceAllStringFunc(s, func(tok string) string {
		if v, ok := m.Tokens[tok]; ok {
			return v
		}
		if v, ok := m.Tokens[strings.ToLower(tok)]; ok {
			return v
		}
		return tok
	})
}
