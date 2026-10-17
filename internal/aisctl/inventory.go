package aisctl

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/scuq/ais/internal/config"
	"github.com/scuq/ais/internal/inventory"
	"github.com/scuq/ais/internal/pseudo"
)

// The inventory subcommands change inventory.mdj without an editor and
// show it without real addresses, so that a person, or a model that helps
// a person, never needs to open the file to keep it current.

const inventoryUsage = `usage: aisctl inventory <sub> [--file PATH]
    list                       entries with product, version and count; addresses pseudonymized
    show                       the file with hostnames and addresses pseudonymized; keeps the map for apply
    set TITLE [key=value ...] [--usage TEXT] [--interest TEXT] [--section Heading=Text] [--unset key]
    set --where FIELD~REGEX [...]  the same for every entry whose field matches; --dry-run lists them
    add TITLE [key=value ...] [--usage TEXT] [--interest TEXT] [--section Heading=Text]
    rm TITLE | rm --where FIELD~REGEX [--dry-run]
    apply FILE                 write an edited copy of 'show' back, real values restored
    import panorama FILE [--roles] [--prune] [--dry-run]
                               merge a Panorama "Managed Devices" CSV export; --roles writes
                               one entry per software version with a count and no identities`

// redactMapFile is where 'show' keeps the pseudonym map that 'apply'
// reverses, under the state directory.
const redactMapFile = "inventory.redact-map.json"

// invEnv is what the subcommands share.
type invEnv struct {
	e     *Env
	path  string
	cfg   *config.Config // nil without a config.yaml
	state string
}

func runInventory(ctx context.Context, e *Env, args []string) error {
	if len(args) == 0 {
		return errors.New(inventoryUsage)
	}
	sub := args[0]
	fs := flag.NewFlagSet("inventory "+sub, flag.ContinueOnError)
	file := fs.String("file", "", "inventory file (default: inventory.file of config.yaml)")
	usageText := fs.String("usage", "", "text of the Usage section")
	interest := fs.String("interest", "", "text of the Interest section")
	var sections, unsets listFlag
	fs.Var(&sections, "section", "Heading=Text, repeatable")
	fs.Var(&unsets, "unset", "JSON key to remove, repeatable")
	prune := fs.Bool("prune", false, "remove imported entries that the export no longer has")
	dryRun := fs.Bool("dry-run", false, "show what would change, write nothing")
	force := fs.Bool("force", false, "show although some values would print in clear")
	roles := fs.Bool("roles", false, "import one entry per software version with a count, no hostnames or addresses")
	var where listFlag
	fs.Var(&where, "where", "FIELD~REGEX, repeatable; apply to every entry whose field matches (title selects on the heading)")
	pos, err := parseMixed(fs, args[1:])
	if err != nil {
		return err
	}
	ie, err := newInvEnv(e, *file)
	if err != nil {
		return err
	}
	switch sub {
	case "list":
		return ie.list()
	case "show":
		return ie.show(*force)
	case "add":
		if len(pos) == 0 || len(where) > 0 {
			return errors.New("usage: aisctl inventory add TITLE [key=value ...]")
		}
		return ie.edit(ctx, sub, pos[0], nil, pos[1:], *usageText, *interest, sections, unsets, *dryRun)
	case "set":
		sel, kvs, err := selection(pos, where, "set")
		if err != nil {
			return err
		}
		return ie.edit(ctx, sub, sel.title, sel.where, kvs, *usageText, *interest, sections, unsets, *dryRun)
	case "rm":
		sel, kvs, err := selection(pos, where, "rm")
		if err != nil || len(kvs) != 0 {
			return errors.New("usage: aisctl inventory rm TITLE | rm --where FIELD~REGEX [--dry-run]")
		}
		return ie.remove(ctx, sel.title, sel.where, *dryRun)
	case "apply":
		if len(pos) != 1 {
			return errors.New("usage: aisctl inventory apply FILE")
		}
		return ie.apply(ctx, pos[0])
	case "import":
		if len(pos) != 2 || pos[0] != "panorama" {
			return errors.New("usage: aisctl inventory import panorama FILE [--roles] [--prune] [--dry-run]")
		}
		return ie.importPanorama(ctx, pos[1], *roles, *prune, *dryRun)
	}
	return fmt.Errorf("unknown inventory subcommand %q\n%s", sub, inventoryUsage)
}

// selector picks entries: one by title, or every one whose fields match
// all regular expressions.
type selector struct {
	title string
	where []fieldMatch
}

type fieldMatch struct {
	field string
	re    *regexp.Regexp
}

// selection reads TITLE or --where from the arguments and returns the
// rest as key=value pairs.
func selection(pos, where []string, sub string) (selector, []string, error) {
	var sel selector
	if len(where) > 0 {
		for _, w := range where {
			field, expr, ok := strings.Cut(w, "~")
			field = strings.TrimSpace(field)
			if !ok || field == "" || expr == "" {
				return sel, nil, fmt.Errorf("--where %q is not FIELD~REGEX", w)
			}
			re, err := regexp.Compile(expr)
			if err != nil {
				return sel, nil, fmt.Errorf("--where %q: %v", w, err)
			}
			sel.where = append(sel.where, fieldMatch{field: strings.ToLower(field), re: re})
		}
		return sel, pos, nil
	}
	if len(pos) == 0 {
		return sel, nil, fmt.Errorf("usage: aisctl inventory %s TITLE [key=value ...] | %s --where FIELD~REGEX [key=value ...]", sub, sub)
	}
	sel.title = pos[0]
	return sel, pos[1:], nil
}

// matches reports whether every condition matches the entry. The title
// condition reads the heading unless the JSON block sets a title; a
// section name reads the section text.
func (sel selector) matches(e *inventory.Entry) bool {
	for _, m := range sel.where {
		var v string
		switch {
		case m.field == inventory.TitleField:
			v = e.Title
			if t, ok := e.Fields[inventory.TitleField]; ok {
				v = t
			}
		default:
			var ok bool
			if v, ok = e.Fields[m.field]; !ok {
				if s := e.Section(m.field); s != nil {
					v = s.Text()
				} else {
					return false
				}
			}
		}
		if !m.re.MatchString(v) {
			return false
		}
	}
	return true
}

// pick returns the selected entries: the one with the title, or all that
// match. No match is an error, so a typo never passes in silence.
func (sel selector) pick(doc *inventory.Document) ([]*inventory.Entry, error) {
	if len(sel.where) == 0 {
		e := doc.Find(sel.title)
		if e == nil {
			return nil, fmt.Errorf("no entry %q", sel.title)
		}
		return []*inventory.Entry{e}, nil
	}
	var out []*inventory.Entry
	for _, e := range doc.Entries {
		if sel.matches(e) {
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no entry matches --where")
	}
	return out, nil
}

// titles names entries for a message, pseudonymized, because a title is
// often a hostname.
func (ie *invEnv) titles(entries []*inventory.Entry) string {
	r, err := ie.redaction()
	if err != nil {
		return fmt.Sprintf("%d entries", len(entries))
	}
	// Register the identity fields first, so that a title that is a bare
	// hostname gets its pseudonym.
	for _, e := range entries {
		for k, v := range e.Fields {
			label := pseudo.DefaultLabels[strings.ToLower(k)]
			if (label == "host" || label == "ip") && strings.TrimSpace(v) != "" {
				r.identity(k, v)
			}
		}
	}
	var out []string
	for _, e := range entries {
		out = append(out, r.text(e.Title))
	}
	return strings.Join(out, ", ")
}

// parseMixed parses flags that come before, between or after positional
// arguments, as in 'set TITLE version=1 --usage x'.
func parseMixed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return pos, nil
		}
		pos = append(pos, rest[0])
		args = rest[1:]
	}
}

func newInvEnv(e *Env, file string) (*invEnv, error) {
	p := UserPaths(e.Home)
	ie := &invEnv{e: e, path: file, state: filepath.Join(e.Home, ".local", "state", "ais")}
	if fileExists(p.ConfigFile) {
		cfg, err := loadConfig(p.ConfigFile)
		if err != nil {
			return nil, err
		}
		ie.cfg = cfg
		ie.state = cfg.StateDir()
		if ie.path == "" {
			ie.path = config.ExpandPath(cfg.Inventory.File)
		}
	}
	if ie.path == "" {
		ie.path = p.Inventory
	}
	return ie, nil
}

func (ie *invEnv) load() (*inventory.Document, error) {
	f, err := os.Open(ie.path)
	if err != nil {
		return nil, fmt.Errorf("inventory: %w", err)
	}
	defer f.Close()
	return inventory.ParseDocument(f)
}

// write renders the document over the inventory file, after a backup, and
// says whether the redaction policy covers every value in it.
func (ie *invEnv) write(ctx context.Context, doc *inventory.Document) error {
	if err := os.MkdirAll(filepath.Dir(ie.path), 0o700); err != nil {
		return err
	}
	backup(ie.path)
	if err := os.WriteFile(ie.path, doc.Render(), 0o600); err != nil {
		return err
	}
	ie.e.logf("wrote %s (%d entries)", ie.path, len(doc.Entries))
	if ie.cfg == nil {
		return nil
	}
	rep, err := RunRedactTest(ctx, ie.cfg, RedactTestOptions{Inventory: ie.path})
	switch {
	case err != nil:
		ie.e.logf("warning: redaction check failed: %v", err)
	case rep.Uncovered() > 0:
		ie.e.logf("warning: %d hostname(s) or address(es) are outside pii.domains / pii.cidrs; run 'aisctl redact test' and fix config.yaml", rep.Uncovered())
	default:
		ie.e.logf("the redaction policy covers every hostname and address")
	}
	return nil
}

// policy is the redaction policy of the host, or the default without a
// config.
func (ie *invEnv) policy() pseudo.Redaction {
	if ie.cfg != nil {
		return ie.cfg.Redaction()
	}
	return pseudo.DefaultRedaction()
}

// redaction pseudonymizes a document the way a run does: hostname and
// address fields through the tokenizer, which rewrites any value, and all
// other text through the redactor, which rewrites what the policy covers.
// The identity values are also replaced wherever they appear in titles and
// text. tokens maps each pseudonym back to the real value.
type redaction struct {
	tok    *pseudo.Tokenizer
	rd     *pseudo.Redactor
	m      *pseudo.Map       // token → real, filled by the tokenizer and the redactor
	fwd    *pseudo.Map       // real → token, to rewrite identities in prose
	tokens map[string]string // token → real, what 'apply' needs
}

func (ie *invEnv) redaction() (*redaction, error) {
	pol := ie.policy()
	rules := pol.Rules()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	rules.Key = hex.EncodeToString(key)
	rd, err := pseudo.NewRedactor(rules)
	if err != nil {
		return nil, err
	}
	r := &redaction{rd: rd, m: pseudo.NewMap("inventory", ""), fwd: pseudo.NewMap("inventory", ""), tokens: map[string]string{}}
	r.tok = pseudo.NewTokenizer(key, nil)
	r.tok.HostnameMode, r.tok.IPMode = pol.HostnameMode, pol.IPMode
	rd.OnMap = func(token, real string) { r.tokens[token] = real }
	return r, nil
}

// identity pseudonymizes one hostname or address field value.
func (r *redaction) identity(field, value string) string {
	tok := r.tok.Token(r.m, field, value)
	r.tokens[tok] = value
	r.fwd.Add(value, field, tok)
	return tok
}

// text redacts prose: identities first, then whatever the policy covers.
func (r *redaction) text(s string) string {
	return r.rd.Redact(r.fwd.Replace(s))
}

var ipv4InText = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

// clearAddresses counts the IPv4 addresses that a redacted rendering still
// shows in clear: an address in prose that pii.cidrs does not cover. A
// pseudonym (CGNAT) does not count.
func clearAddresses(rendered []byte) int {
	n := 0
	for _, m := range ipv4InText.FindAllString(string(rendered), -1) {
		if net.ParseIP(m) != nil && !pseudo.IsCGNAT(m) {
			n++
		}
	}
	return n
}

// redactDoc rewrites every title, value and text line of the document.
func redactDoc(doc *inventory.Document, r *redaction) *inventory.Document {
	out := &inventory.Document{}
	// Identity fields first, so that the same names in titles and prose
	// get the same pseudonyms.
	values := map[*inventory.Entry]map[string]string{}
	for _, e := range doc.Entries {
		values[e] = map[string]string{}
		for k, v := range e.Fields {
			label := pseudo.DefaultLabels[strings.ToLower(k)]
			if (label == "host" || label == "ip") && strings.TrimSpace(v) != "" {
				values[e][k] = r.identity(k, v)
			}
		}
	}
	for _, l := range doc.Preamble {
		out.Preamble = append(out.Preamble, r.text(l))
	}
	for _, e := range doc.Entries {
		ne := &inventory.Entry{Title: r.text(e.Title), Line: e.Line}
		keys := append([]string(nil), e.Keys...)
		for _, k := range sortedFieldKeys(e.Fields) {
			seen := false
			for _, kk := range keys {
				if kk == k {
					seen = true
				}
			}
			if !seen {
				keys = append(keys, k)
			}
		}
		for _, k := range keys {
			v, ok := e.Fields[k]
			if !ok {
				continue
			}
			if t, ok := values[e][k]; ok {
				ne.Set(k, t)
			} else {
				ne.Set(k, r.text(v))
			}
		}
		for _, s := range e.Sections {
			ns := &inventory.Section{Heading: s.Heading}
			for _, l := range s.Lines {
				ns.Lines = append(ns.Lines, r.text(l))
			}
			ne.Sections = append(ne.Sections, ns)
		}
		out.Entries = append(out.Entries, ne)
	}
	return out
}

func sortedFieldKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (ie *invEnv) list() error {
	doc, err := ie.load()
	if err != nil {
		return err
	}
	r, err := ie.redaction()
	if err != nil {
		return err
	}
	doc = redactDoc(doc, r)
	tw := tabwriter.NewWriter(ie.e.Out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "TITLE\tVENDOR\tPRODUCT\tVERSION\tCOUNT\tHOSTNAME\tIP\tSECTIONS")
	for _, e := range doc.Entries {
		var host, ip string
		for _, k := range e.Keys {
			switch pseudo.DefaultLabels[strings.ToLower(k)] {
			case "host":
				if host == "" {
					host = e.Fields[k]
				}
			case "ip":
				if ip == "" {
					ip = e.Fields[k]
				}
			}
		}
		var secs []string
		for _, s := range e.Sections {
			secs = append(secs, s.Heading)
		}
		rec := inventory.Record{Fields: e.Fields}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\n", e.Title, e.Fields["vendor"], e.Fields["product"], orDash(e.Fields["version"]), rec.Count(), orDash(host), orDash(ip), orDash(strings.Join(secs, ", ")))
	}
	return tw.Flush()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// show prints the pseudonymized file and keeps the map, so that 'apply'
// can take an edited copy back. It refuses when a hostname or address is
// outside the policy and would print in clear, unless forced.
func (ie *invEnv) show(force bool) error {
	doc, err := ie.load()
	if err != nil {
		return err
	}
	r, err := ie.redaction()
	if err != nil {
		return err
	}
	red := redactDoc(doc, r)
	rendered := red.Render()
	if n := clearAddresses(rendered); n > 0 && !force {
		return fmt.Errorf("%d address(es) in the text are outside pii.cidrs and would print in clear; add the range to config.yaml or pass --force", n)
	}
	m := r.tokens
	if err := os.MkdirAll(ie.state, 0o700); err != nil {
		return err
	}
	raw, _ := json.MarshalIndent(map[string]any{"created": ie.e.Now().UTC().Format(time.RFC3339), "file": ie.path, "tokens": m}, "", "  ")
	mapPath := filepath.Join(ie.state, redactMapFile)
	if err := os.WriteFile(mapPath, raw, 0o600); err != nil {
		return err
	}
	if _, err := ie.e.Out.Write(rendered); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "aisctl: %d pseudonym(s); the map is in %s. Edit the output and run 'aisctl inventory apply FILE'.\n", len(m), mapPath)
	return nil
}

// apply reads an edited copy of 'show', puts the real values back from
// the map, checks the result and writes the inventory file.
func (ie *invEnv) apply(ctx context.Context, file string) error {
	mapPath := filepath.Join(ie.state, redactMapFile)
	raw, err := os.ReadFile(mapPath)
	if err != nil {
		return fmt.Errorf("no pseudonym map (%v); run 'aisctl inventory show' first", err)
	}
	var stored struct {
		Tokens map[string]string `json:"tokens"`
	}
	if err := json.Unmarshal(raw, &stored); err != nil {
		return fmt.Errorf("pseudonym map: %w", err)
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	pm := pseudo.NewMap("inventory", "")
	for tok, real := range stored.Tokens {
		pm.Add(tok, "", real)
	}
	text := pm.Replace(string(data))
	doc, err := inventory.ParseDocument(strings.NewReader(text))
	if err != nil {
		return err
	}
	if err := ie.write(ctx, doc); err != nil {
		return err
	}
	ie.e.logf("restored %d pseudonym(s) from %s", len(stored.Tokens), mapPath)
	return nil
}

// edit sets JSON values and sections of the selected entries (set), or
// creates one entry (add).
func (ie *invEnv) edit(ctx context.Context, mode, title string, where []fieldMatch, kvs []string, usage, interest string, sections, unsets []string, dryRun bool) error {
	doc, err := ie.load()
	if err != nil {
		if mode == "add" && errors.Is(err, os.ErrNotExist) {
			doc = &inventory.Document{}
		} else {
			return err
		}
	}
	var targets []*inventory.Entry
	if mode == "add" {
		if doc.Find(title) != nil {
			return fmt.Errorf("entry %q exists (use 'aisctl inventory set')", title)
		}
		targets = []*inventory.Entry{doc.Add(title, nil, nil)}
	} else {
		if targets, err = (selector{title: title, where: where}).pick(doc); err != nil {
			if where == nil {
				return fmt.Errorf("%v (use 'aisctl inventory add')", err)
			}
			return err
		}
	}
	if usage != "" {
		sections = append(sections, "Usage="+usage)
	}
	if interest != "" {
		sections = append(sections, "Interest="+interest)
	}
	for _, e := range targets {
		if err := applyEdits(e, kvs, unsets, sections); err != nil {
			return fmt.Errorf("entry %q: %w", e.Title, err)
		}
		if len(e.Fields) == 0 {
			return fmt.Errorf("entry %q needs at least one key=value (for example product=...)", e.Title)
		}
	}
	if dryRun {
		ie.e.logf("dry run: would change %d entries: %s", len(targets), ie.titles(targets))
		return nil
	}
	if len(targets) > 1 {
		ie.e.logf("changed %d entries: %s", len(targets), ie.titles(targets))
	}
	return ie.write(ctx, doc)
}

// applyEdits puts key=value pairs, removals and sections into one entry.
func applyEdits(e *inventory.Entry, kvs, unsets, sections []string) error {
	for _, kv := range kvs {
		k, v, ok := strings.Cut(kv, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			return fmt.Errorf("%q is not key=value", kv)
		}
		if k == inventory.CountField {
			if (inventory.Record{Fields: map[string]string{k: v}}).Count() == 1 && strings.TrimSpace(v) != "1" {
				return fmt.Errorf("count must be a positive integer, not %q", v)
			}
		}
		if e.Section(k) != nil {
			return fmt.Errorf("%q is a section of this entry; use --section", k)
		}
		e.Set(k, strings.TrimSpace(v))
	}
	for _, k := range unsets {
		e.Unset(k)
	}
	for _, s := range sections {
		h, text, ok := strings.Cut(s, "=")
		h = strings.TrimSpace(h)
		if !ok || h == "" {
			return fmt.Errorf("%q is not Heading=Text", s)
		}
		if _, isField := e.Fields[strings.ToLower(h)]; isField {
			return fmt.Errorf("%q is a JSON key of this entry; a section cannot repeat it", h)
		}
		e.SetSection(h, text)
	}
	return nil
}

func (ie *invEnv) remove(ctx context.Context, title string, where []fieldMatch, dryRun bool) error {
	doc, err := ie.load()
	if err != nil {
		return err
	}
	targets, err := (selector{title: title, where: where}).pick(doc)
	if err != nil {
		return err
	}
	if dryRun {
		ie.e.logf("dry run: would remove %d entries: %s", len(targets), ie.titles(targets))
		return nil
	}
	doomed := map[*inventory.Entry]bool{}
	for _, e := range targets {
		doomed[e] = true
	}
	kept := doc.Entries[:0]
	for _, e := range doc.Entries {
		if !doomed[e] {
			kept = append(kept, e)
		}
	}
	doc.Entries = kept
	if len(targets) > 1 {
		ie.e.logf("removed %d entries: %s", len(targets), ie.titles(targets))
	}
	return ie.write(ctx, doc)
}

// importPanorama merges a Managed Devices export into the inventory, one
// entry per device or, with roles, one per software version, and prints
// the model and version counts, which hold no identity.
func (ie *invEnv) importPanorama(ctx context.Context, file string, roles, prune, dryRun bool) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	devs, err := inventory.ParsePanoramaCSV(f)
	if err != nil {
		return err
	}
	doc, err := ie.load()
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		doc = &inventory.Document{}
	}
	var st inventory.MergeStats
	if roles {
		st = inventory.MergePanoramaRoles(doc, devs, prune)
	} else {
		st = inventory.MergePanorama(doc, devs, prune)
	}
	tw := tabwriter.NewWriter(ie.e.Out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "MODEL\tVERSION\tDEVICES")
	for _, g := range inventory.PanoramaSummary(devs) {
		fmt.Fprintf(tw, "%s\t%s\t%d\n", orDash(g.Model), orDash(g.Version), g.Count)
	}
	tw.Flush()
	ie.e.logf("%d device(s) in the export: %d added, %d updated, %d unchanged, %d pruned", len(devs), st.Added, st.Updated, st.Unchanged, st.Pruned)
	if dryRun {
		ie.e.logf("dry run: nothing written")
		return nil
	}
	return ie.write(ctx, doc)
}
