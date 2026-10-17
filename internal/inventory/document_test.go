package inventory

import (
	"strings"
	"testing"
)

const docSample = `Notes above the first heading stay.

# Internet edge firewalls

` + "```json" + `
{
  "vendor": "Palo Alto Networks",
  "product": "PAN-OS",
  "version": "11.2.13-h2",
  "count": 2
}
` + "```" + `

## Usage

Internet facing.
No VPN.

## Interest

Unauthenticated remote only.

# Keycloak

` + "```json" + `
{"vendor": "Keycloak", "product": "Keycloak"}
` + "```" + `
`

func TestDocumentRoundTrip(t *testing.T) {
	doc, err := ParseDocument(strings.NewReader(docSample))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Entries) != 2 || strings.Join(doc.Entries[0].Keys, ",") != "vendor,product,version,count" || doc.Entries[0].Fields["count"] != "2" {
		t.Fatalf("%+v", doc.Entries[0])
	}
	if len(doc.Preamble) == 0 || !strings.Contains(doc.Preamble[0], "Notes above") {
		t.Errorf("preamble: %q", doc.Preamble)
	}
	if s := doc.Entries[0].Section("usage"); s == nil || s.Text() != "Internet facing. No VPN." {
		t.Errorf("usage section: %+v", s)
	}
	out := string(doc.Render())
	doc2, err := ParseDocument(strings.NewReader(out))
	if err != nil {
		t.Fatalf("re-parse: %v\n%s", err, out)
	}
	if string(doc2.Render()) != out {
		t.Errorf("render is not stable:\n%s\n---\n%s", out, doc2.Render())
	}
	recs := doc2.Records()
	if len(recs) != 2 || recs[0].Fields["usage"] != "Internet facing. No VPN." || recs[0].Fields["interest"] != "Unauthenticated remote only." || recs[0].Count() != 2 {
		t.Errorf("records: %+v", recs)
	}
	if recs[1].Count() != 1 {
		t.Errorf("default count: %d", recs[1].Count())
	}
	// Minimize adds the counts.
	g := Minimize(recs, []string{"product"}, []string{"usage"})
	if len(g) != 2 || g[0].Count != 1 || g[1].Count != 2 || g[1].Collected["usage"][0] != "Internet facing. No VPN." {
		t.Errorf("groups: %+v", g)
	}
}

func TestDocumentEdit(t *testing.T) {
	doc, _ := ParseDocument(strings.NewReader(docSample))
	e := doc.Find(" internet EDGE firewalls ")
	if e == nil {
		t.Fatal("find by title")
	}
	e.Set("version", "11.2.16")
	e.Set("site", "earth")
	e.Unset("count")
	e.SetSection("Usage", "Edge.\nStill no VPN.")
	e.SetSection("Interest", "")
	e.SetSection("Owner Notes", "call netops")
	if !doc.Remove("keycloak") || doc.Remove("keycloak") {
		t.Error("remove")
	}
	doc.Add("GlobalProtect", []string{"product", "vendor"}, map[string]string{"vendor": "Palo Alto Networks", "product": "GlobalProtect", "zzz": "last"})
	out := string(doc.Render())
	for _, want := range []string{
		"\"version\": \"11.2.16\",\n  \"site\": \"earth\"\n}", "## Usage\n\nEdge.\nStill no VPN.\n", "## Owner Notes\n\ncall netops\n",
		"# GlobalProtect\n\n```json\n{\n  \"product\": \"GlobalProtect\",\n  \"vendor\": \"Palo Alto Networks\",\n  \"zzz\": \"last\"\n}\n```\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "count") || strings.Contains(out, "## Interest") || strings.Contains(out, "Keycloak") {
		t.Errorf("stale content:\n%s", out)
	}
	doc2, err := ParseDocument(strings.NewReader(out))
	if err != nil {
		t.Fatal(err)
	}
	if doc2.FindByField("site", "EARTH") == nil || doc2.FindByField("site", "") != nil || doc2.Records()[0].Fields["owner_notes"] != "call netops" {
		t.Errorf("%+v", doc2.Records())
	}
}

func TestDocumentJSONKeyTwice(t *testing.T) {
	if _, err := ParseDocument(strings.NewReader("# a\n```json\n{\"x\": 1, \"x\": 2}\n```\n")); err == nil {
		t.Error("duplicate JSON key accepted")
	}
}
