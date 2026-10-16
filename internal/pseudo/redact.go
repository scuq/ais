package pseudo

import (
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
)

// Rules describe what the redactor and the leak check look for beyond the
// token map: address ranges and DNS domains of the inventory, plus literal
// strings that must never appear.
type Rules struct {
	Domains  []string `json:"domains"`  // ".corp.example" matches any name under it
	CIDRs    []string `json:"cidrs"`    // "10.0.0.0/8"
	Literals []string `json:"literals"` // exact, case-insensitive
	// HostnameMode: rot13 rewrites matching names, anything else replaces
	// them with Replacement. IPMode: cgnat maps matching IPv4 addresses
	// into 100.64.0.0/10 keyed by Key, anything else replaces them.
	HostnameMode string `json:"hostnameMode,omitempty"`
	IPMode       string `json:"ipMode,omitempty"`
	// Key (hex) keys the cgnat mapping inside the container. It is random
	// per run and unrelated to the host salt, so hook-redacted addresses
	// never correlate with inventory tokens.
	Key string `json:"key,omitempty"`
}

// Redactor rewrites strings so that nothing matching the rules survives.
// It is shape-preserving: callers apply it to string leaves only.
type Redactor struct {
	domains  []string
	nets     []*net.IPNet
	literals []string
	hostMode string
	ipMode   string
	key      []byte
	// OnMap, when set, receives every reversible rewrite (rot13 hostname,
	// cgnat address) so the host can record it in the token map.
	OnMap func(token, real string)
}

// Replacement is what a redacted span becomes.
const Replacement = "[redacted]"

var (
	ipv4RE = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	// A pragmatic IPv6 matcher: at least two groups separated by colons, with
	// hex digits and optional "::". It over-matches on odd strings like
	// "aa:bb", which the net.ParseIP check below filters out.
	ipv6RE = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b`)
	fqdnRE = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b`)
)

// NewRedactor compiles rules.
func NewRedactor(r Rules) (*Redactor, error) {
	rd := &Redactor{}
	for _, d := range r.Domains {
		d = strings.ToLower(strings.TrimSpace(d))
		if d == "" {
			continue
		}
		if !strings.HasPrefix(d, ".") {
			d = "." + d
		}
		rd.domains = append(rd.domains, d)
	}
	for _, c := range r.CIDRs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			return nil, fmt.Errorf("cidr %q: %w", c, err)
		}
		rd.nets = append(rd.nets, n)
	}
	for _, l := range r.Literals {
		if l = strings.TrimSpace(l); l != "" {
			rd.literals = append(rd.literals, l)
		}
	}
	// Longest first so "db01.corp.example" is removed before "db01".
	sort.Slice(rd.literals, func(i, j int) bool { return len(rd.literals[i]) > len(rd.literals[j]) })
	rd.hostMode, rd.ipMode = r.HostnameMode, r.IPMode
	if r.Key != "" {
		k, err := hex.DecodeString(r.Key)
		if err != nil {
			return nil, fmt.Errorf("key: %w", err)
		}
		rd.key = k
	}
	if rd.ipMode == IPCGNAT && len(rd.key) == 0 {
		// No key: fall back to plain replacement rather than an unkeyed,
		// brute-forceable mapping.
		rd.ipMode = ModeRedact
	}
	return rd, nil
}

func (rd *Redactor) ipReplacement(s string) string {
	if rd.ipMode == IPCGNAT {
		if out := CGNATAddress(rd.key, net.ParseIP(s)); out != "" {
			if rd.OnMap != nil {
				rd.OnMap(out, s)
			}
			return out
		}
	}
	return Replacement
}

func (rd *Redactor) hostReplacement(s string) string {
	if rd.hostMode == HostnameRot13 {
		out := Rot13(s)
		if rd.OnMap != nil && out != s {
			rd.OnMap(out, s)
		}
		return out
	}
	return Replacement
}

func (rd *Redactor) matchIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	for _, n := range rd.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (rd *Redactor) matchDomain(s string) bool {
	s = strings.ToLower(s)
	for _, d := range rd.domains {
		if strings.HasSuffix(s, d) || s == d[1:] {
			return true
		}
	}
	return false
}

// Redact returns s with every match replaced.
func (rd *Redactor) Redact(s string) string {
	if rd == nil {
		return s
	}
	for _, l := range rd.literals {
		s = replaceFold(s, l, Replacement)
	}
	if len(rd.nets) > 0 {
		s = ipv4RE.ReplaceAllStringFunc(s, func(m string) string {
			if rd.matchIP(m) {
				return rd.ipReplacement(m)
			}
			return m
		})
		s = ipv6RE.ReplaceAllStringFunc(s, func(m string) string {
			if rd.matchIP(m) {
				return Replacement
			}
			return m
		})
	}
	if len(rd.domains) > 0 {
		s = fqdnRE.ReplaceAllStringFunc(s, func(m string) string {
			if rd.matchDomain(m) {
				return rd.hostReplacement(m)
			}
			return m
		})
	}
	return s
}

// RedactDoc applies Redact to every string leaf of a decoded JSON document,
// keeping the shape intact.
func (rd *Redactor) RedactDoc(doc any) any {
	switch v := doc.(type) {
	case string:
		return rd.Redact(v)
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, val := range v {
			out[k] = rd.RedactDoc(val)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, val := range v {
			out[i] = rd.RedactDoc(val)
		}
		return out
	}
	return doc
}

// replaceFold replaces every case-insensitive occurrence of old in s.
func replaceFold(s, old, repl string) string {
	if old == "" {
		return s
	}
	ls, lo := strings.ToLower(s), strings.ToLower(old)
	var b strings.Builder
	i := 0
	for {
		j := strings.Index(ls[i:], lo)
		if j < 0 {
			b.WriteString(s[i:])
			return b.String()
		}
		b.WriteString(s[i : i+j])
		b.WriteString(repl)
		i += j + len(old)
	}
}

// Finding is one leak: a real value that appeared in model output.
type Finding struct {
	Value   string `json:"value"`
	Field   string `json:"field,omitempty"`
	Snippet string `json:"snippet"`
	Offset  int    `json:"offset"`
}

// LeakCheck scans raw model output for any real value from the token map
// (case-insensitive) and for any literal in the rules. It is the host-side
// backstop behind the in-container redactor: a hit means the run must not
// be dispatched.
func LeakCheck(raw []byte, m *Map, rules Rules) []Finding {
	text := string(raw)
	lower := strings.ToLower(text)
	var out []Finding
	seen := map[string]bool{}
	check := func(value, field string) {
		if len(value) < 3 || seen[value] {
			return
		}
		seen[value] = true
		idx := strings.Index(lower, strings.ToLower(value))
		if idx < 0 {
			return
		}
		out = append(out, Finding{Value: value, Field: field, Snippet: snippet(text, idx, len(value)), Offset: idx})
	}
	if m != nil {
		for tok, v := range m.Tokens {
			check(v, m.Field(tok))
		}
	}
	for _, l := range rules.Literals {
		check(l, "literal")
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Offset < out[j].Offset })
	return out
}

func snippet(s string, idx, n int) string {
	const ctx = 40
	start, end := idx-ctx, idx+n+ctx
	if start < 0 {
		start = 0
	}
	if end > len(s) {
		end = len(s)
	}
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' {
			return ' '
		}
		return r
	}, s[start:end])
}
