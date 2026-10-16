package inventory

import (
	"strings"
	"testing"
)

func TestParseCSVAndMinimize(t *testing.T) {
	recs, err := Parse(strings.NewReader("hostname, product,version\na,P,1\nb,P,1\nc,Q,2\n"), "csv")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 3 || recs[0].Fields["product"] != "P" {
		t.Fatalf("%+v", recs)
	}
	g := Minimize(recs, []string{"product", "version"}, nil)
	if len(g) != 2 || g[0].Count != 2 || g[1].Fields["product"] != "Q" {
		t.Errorf("%+v", g)
	}
	recs2, _ := Parse(strings.NewReader("product,comment\nP,internet exposed\nP,auth using saml\nP,internet exposed\nP,\n"), "csv")
	g2 := Minimize(recs2, []string{"product"}, []string{"comment"})
	if len(g2) != 1 || strings.Join(g2[0].Collected["comment"], "|") != "auth using saml|internet exposed" {
		t.Errorf("collect: %+v", g2)
	}
}

func TestParseYAMLNumbers(t *testing.T) {
	recs, err := Parse(strings.NewReader("- {product: P, version: 2022, count: 1.5}\n"), "yaml")
	if err != nil {
		t.Fatal(err)
	}
	if recs[0].Fields["version"] != "2022" || recs[0].Fields["count"] != "1.5" {
		t.Errorf("%+v", recs[0])
	}
}

func TestOpenInfersFormat(t *testing.T) {
	s, err := Open(SourceConfig{File: "/x/inv.csv"})
	if err != nil || s.(*FileSource).Format != "csv" {
		t.Errorf("s=%v err=%v", s, err)
	}
	if _, err := Open(SourceConfig{File: "/x/inv.txt"}); err == nil {
		t.Error("expected error for unknown extension")
	}
}

func TestParseText(t *testing.T) {
	lines, err := ParseText("# comment\n\n  Keycloak 26.1  \nPalo Alto GlobalProtect\n\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(lines) != 2 || lines[0] != "Keycloak 26.1" || lines[1] != "Palo Alto GlobalProtect" {
		t.Errorf("%q", lines)
	}
	if _, err := ParseText(strings.Repeat("x", MaxTextLineLen+1)); err == nil {
		t.Error("over-long line accepted")
	}
	if _, err := ParseText(strings.Repeat("p\n", MaxTextLines+1)); err == nil {
		t.Error("too many lines accepted")
	}
}
