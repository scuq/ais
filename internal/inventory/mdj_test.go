package inventory

import (
	"strings"
	"testing"
)

func TestParseMDJ(t *testing.T) {
	doc := "Inventory of the lab.\n\n" +
		"# fw01.cyberdyne.systems\n\n" +
		"```json\n{\n \"hostname\": \"fw01.cyberdyne.systems\",\n \"version\": 11.1,\n \"ha\": true\n}\n```\n\n" +
		"## Usage\n\nEdge firewall,\ninternet facing.\n\n```\n# not a heading\n```\n\n" +
		"## Interest ##\n\nOnly critical.\n\n" +
		"### Detail\nstays in interest\n\n" +
		"# Keycloak\n\n~~~\n{\"product\": \"Keycloak\"}\n~~~\n"
	recs, err := Parse(strings.NewReader(doc), "mdj")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("%+v", recs)
	}
	f := recs[0].Fields
	if f["hostname"] != "fw01.cyberdyne.systems" || f["version"] != "11.1" || f["ha"] != "true" {
		t.Errorf("json: %v", f)
	}
	if f["usage"] != "Edge firewall, internet facing. # not a heading" {
		t.Errorf("usage: %q", f["usage"])
	}
	if f["interest"] != "Only critical. ### Detail stays in interest" {
		t.Errorf("interest: %q", f["interest"])
	}
	if len(recs[1].Fields) != 2 || recs[1].Fields["product"] != "Keycloak" || recs[1].Fields["title"] != "Keycloak" {
		t.Errorf("product only: %v", recs[1].Fields)
	}
}

func TestParseMDJErrors(t *testing.T) {
	block := "```json\n{\"product\": \"P\"}\n```\n"
	for name, doc := range map[string]string{
		"no json":       "# a\n\n## Usage\nx\n",
		"text before":   "# a\nprose\n" + block,
		"text after":    "# a\n" + block + "prose\n",
		"section first": "# a\n## Usage\n" + block,
		"two blocks":    "# a\n" + block + block,
		"nested":        "# a\n```json\n{\"x\": {\"y\": 1}}\n```\n",
		"array":         "# a\n```json\n[{\"x\": 1}]\n```\n",
		"two values":    "# a\n```json\n{\"x\": 1} {\"y\": 2}\n```\n",
		"bad json":      "# a\n```json\n{x: 1}\n```\n",
		"language":      "# a\n```yaml\nx: 1\n```\n",
		"unclosed":      "# a\n```json\n{\"x\": 1}\n",
		"key twice":     "# a\n" + block + "## Product\nQ\n",
		"section twice": "# a\n" + block + "## Usage\nx\n## usage\ny\n",
		"empty heading": "# \n" + block,
		"no field name": "# a\n" + block + "## ---\nx\n",
	} {
		if _, err := Parse(strings.NewReader(doc), "mdj"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if recs, err := Parse(strings.NewReader("only a preamble\n"), "mdj"); err != nil || len(recs) != 0 {
		t.Errorf("preamble only: %v %v", recs, err)
	}
}

func TestOpenInfersMDJ(t *testing.T) {
	for _, p := range []string{"/x/inv.mdj", "/x/inv.md"} {
		s, err := Open(SourceConfig{File: p})
		if err != nil || s.(*FileSource).Format != "mdj" {
			t.Errorf("%s: s=%v err=%v", p, s, err)
		}
	}
}
