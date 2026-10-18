package prefilter

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/scuq/ais/internal/inventory"
)

// stopwords are tokens too generic to identify a product on their own:
// a vendor name like "Palo Alto Networks" must not keep every item that
// says "networks".
var stopwords = map[string]bool{
	"and": true, "the": true, "for": true, "with": true, "von": true, "und": true, "für": true,
	"inc": true, "ltd": true, "gmbh": true, "corp": true, "corporation": true, "llc": true,
	"network": true, "networks": true, "system": true, "systems": true, "software": true,
	"server": true, "servers": true, "service": true, "services": true, "security": true,
	"secure": true, "platform": true, "enterprise": true, "cloud": true, "technologies": true,
	"technology": true, "solutions": true, "edition": true, "version": true, "appliance": true,
	"appliances": true, "suite": true, "product": true, "products": true, "pro": true, "plus": true,
	"standard": true, "advanced": true, "premium": true, "business": true, "edge": true, "core": true,
	"base": true, "web": true, "app": true, "apps": true, "manager": true, "management": true,
	"gateway": true, "client": true, "open": true, "source": true, "project": true, "community": true,
	"various": true, "all": true, "any": true, "unknown": true, "none": true, "n/a": true,
	"usage": true, "interest": true, "notes": true, "installs": true, "install": true,
}

// Tokens lower-cases s and splits it at every character that is not a
// letter or a digit. "PAN-OS 11.2" gives [pan os 11 2].
func Tokens(s string) []string {
	var out []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			out = append(out, string(cur))
			cur = cur[:0]
		}
	}
	for _, r := range strings.ToLower(s) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			cur = append(cur, r)
		} else {
			flush()
		}
	}
	flush()
	return out
}

func numeric(tok string) bool {
	for _, r := range tok {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

// phraseKeywords returns the keywords of a name: the whole token
// sequence, the tokens joined ("PAN-OS" also as "panos"), and each
// token of three or more characters that is not a stopword or a number.
func phraseKeywords(name string) []string {
	toks := Tokens(name)
	var keep []string
	for _, t := range toks {
		if !stopwords[t] && !numeric(t) {
			keep = append(keep, t)
		}
	}
	if len(keep) == 0 {
		return nil
	}
	var out []string
	out = append(out, strings.Join(keep, " "))
	if len(keep) > 1 {
		out = append(out, strings.Join(keep, ""))
	}
	for _, t := range keep {
		if len([]rune(t)) >= 3 {
			out = append(out, t)
		}
	}
	return out
}

// properNouns returns the capitalized words of a free-text line that are
// not stopwords: the product names in "Fortinet FortiGate (various)".
func properNouns(line string) []string {
	var out []string
	for _, w := range strings.FieldsFunc(line, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' }) {
		first, _ := firstRune(w)
		if !unicode.IsUpper(first) {
			continue
		}
		out = append(out, phraseKeywords(w)...)
	}
	return out
}

func firstRune(s string) (rune, bool) {
	for _, r := range s {
		return r, true
	}
	return 0, false
}

// BuildTargets turns the minimized inventory groups and the free-text
// lines into targets. The text of a group is what the prompt shows for
// it: vendor, product, version, and the collected usage, interest and
// notes. Groups and lines are the pseudonymized ones: the model never
// sees more than the prompt does.
func BuildTargets(groups []inventory.Group, text []string) []Target {
	var out []Target
	for i, g := range groups {
		vendor, product, version := g.Fields["vendor"], g.Fields["product"], g.Fields["version"]
		parts := []string{vendor, product, version}
		if strings.EqualFold(strings.TrimSpace(vendor), strings.TrimSpace(product)) {
			parts = parts[1:] // "OpenBSD OpenBSD" reads as one word
		}
		label := strings.TrimSpace(strings.Join(nonEmpty(parts...), " "))
		if label == "" {
			continue
		}
		var b strings.Builder
		b.WriteString(label)
		for _, f := range []string{"usage", "interest", "comment"} {
			if vals := g.Collected[f]; len(vals) > 0 {
				fmt.Fprintf(&b, ". %s: %s", strings.ToUpper(f[:1])+f[1:], strings.Join(vals, "; "))
			}
		}
		kws := dedupe(append(phraseKeywords(vendor), phraseKeywords(product)...))
		out = append(out, Target{ID: fmt.Sprintf("g%d", i), Label: label, Text: b.String(), Keywords: kws})
	}
	for i, line := range text {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, Target{ID: fmt.Sprintf("t%d", i), Label: line, Text: line, Keywords: dedupe(properNouns(line))})
	}
	return out
}

func nonEmpty(ss ...string) []string {
	var out []string
	for _, s := range ss {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// dedupe removes duplicates and orders the keywords longest phrase first,
// so a hit reports "pan os" rather than "pan".
func dedupe(ss []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		ni, nj := len(strings.Fields(out[i])), len(strings.Fields(out[j]))
		if ni != nj {
			return ni > nj
		}
		return out[i] < out[j]
	})
	return out
}

// Lexical reports the first target whose keyword occurs in text as a
// whole token or a contiguous token sequence, and that keyword. "pan os"
// matches "PAN-OS 11.2" and "pan" matches "PAN firewalls", but neither
// matches "company".
func Lexical(targets []Target, text string) (Target, string, bool) {
	toks := Tokens(text)
	if len(toks) == 0 {
		return Target{}, "", false
	}
	for _, t := range targets {
		for _, kw := range t.Keywords {
			if containsSeq(toks, strings.Fields(kw)) {
				return t, kw, true
			}
		}
	}
	return Target{}, "", false
}

func containsSeq(toks, seq []string) bool {
	if len(seq) == 0 || len(seq) > len(toks) {
		return false
	}
outer:
	for i := 0; i+len(seq) <= len(toks); i++ {
		for j, s := range seq {
			if toks[i+j] != s {
				continue outer
			}
		}
		return true
	}
	return false
}
