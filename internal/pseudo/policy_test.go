package pseudo

import (
	"encoding/hex"
	"net"
	"strings"
	"testing"

	"github.com/scuq/ais/internal/inventory"
)

func TestRot13(t *testing.T) {
	if got := Rot13("fw01.cyberdyne.systems"); got != "sj01.ploreqlar.flfgrzf" {
		t.Errorf("got %s", got)
	}
	if Rot13(Rot13("Host-9")) != "Host-9" {
		t.Error("rot13 is not an involution")
	}
}

func TestCGNATDeterministicAndInRange(t *testing.T) {
	key := []byte("k")
	a := CGNATAddress(key, net.ParseIP("10.1.0.1"))
	b := CGNATAddress(key, net.ParseIP("10.1.0.1"))
	c := CGNATAddress([]byte("other"), net.ParseIP("10.1.0.1"))
	if a != b || a == c || !IsCGNAT(a) {
		t.Errorf("a=%s b=%s c=%s", a, b, c)
	}
	if CGNATAddress(key, net.ParseIP("fc00::1")) != "" {
		t.Error("ipv6 must not map")
	}
}

func TestApprovalHash(t *testing.T) {
	d := DefaultRedaction()
	h1 := d.ApprovalHash()
	d2 := d
	d2.Domains = []string{" .CYBERDYNE.SYSTEMS "}
	if d2.ApprovalHash() != h1 {
		t.Error("hash must ignore case and whitespace")
	}
	d2.Domains = append(d2.Domains, ".other.example")
	if d2.ApprovalHash() == h1 {
		t.Error("hash must change with the policy")
	}
	if err := CheckApproval(d, ""); err == nil {
		t.Error("unapproved accepted")
	}
	if err := CheckApproval(d, "deadbeef"); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Errorf("stale approval: %v", err)
	}
	if err := CheckApproval(d, h1); err != nil {
		t.Error(err)
	}
	if err := (Redaction{HostnameMode: "plain", IPMode: IPCGNAT}).Validate(); err == nil {
		t.Error("bad mode accepted")
	}
}

func TestCoverage(t *testing.T) {
	d := DefaultRedaction()
	c := d.Check([]string{"fw01.cyberdyne.systems", "db.other.example", "standalone"}, []string{"10.1.2.3", "8.8.8.8", "172.31.0.1"})
	if strings.Join(c.UncoveredHosts, ",") != "db.other.example" || strings.Join(c.UncoveredIPs, ",") != "8.8.8.8" {
		t.Errorf("%+v", c)
	}
}

func TestRedactorModes(t *testing.T) {
	rules := DefaultRedaction().Rules()
	rules.Key = strings.Repeat("ab", 32)
	rd, err := NewRedactor(rules)
	if err != nil {
		t.Fatal(err)
	}
	out := rd.Redact("fw01.cyberdyne.systems at 10.1.0.1 and 8.8.8.8 and db.other.example")
	if !strings.Contains(out, "sj01.ploreqlar.flfgrzf") || strings.Contains(out, "cyberdyne") {
		t.Errorf("hostname not rot13: %s", out)
	}
	if strings.Contains(out, "10.1.0.1") || !strings.Contains(out, "100.") {
		t.Errorf("private ip not mapped to cgnat: %s", out)
	}
	if !strings.Contains(out, "8.8.8.8") || !strings.Contains(out, "db.other.example") {
		t.Errorf("public values must survive: %s", out)
	}
	// Without a key, cgnat falls back to plain replacement.
	rules.Key = ""
	rd, _ = NewRedactor(rules)
	if out := rd.Redact("10.1.0.1"); out != Replacement {
		t.Errorf("unkeyed cgnat must redact: %s", out)
	}
}

func TestTokenizerModesRoundTrip(t *testing.T) {
	m := NewMap("t", "s")
	tok := NewTokenizer([]byte("salt"), nil)
	tok.HostnameMode, tok.IPMode = HostnameRot13, IPCGNAT
	out := Apply(Policy{"hostname": Pseudonym, "ip": Pseudonym, "ipv6": Pseudonym}, tok, m, nil, []inventory.Record{{Fields: map[string]string{"hostname": "fw01.cyberdyne.systems", "ip": "10.1.0.1", "ipv6": "fc00::1"}}})
	f := out[0].Fields
	if f["hostname"] != "sj01.ploreqlar.flfgrzf" || !IsCGNAT(f["ip"]) || !strings.HasPrefix(f["ipv6"], "ip-") {
		t.Errorf("%v", f)
	}
	text := "see SJ01.ploreqlar.flfgrzf (" + f["ip"] + ") and " + f["ipv6"]
	clear := m.Replace(text)
	if clear != "see fw01.cyberdyne.systems (10.1.0.1) and fc00::1" {
		t.Errorf("depseudonymize: %s", clear)
	}
}

func TestScrubModeIsReversible(t *testing.T) {
	salt := []byte("salt")
	m := NewMap("t", "s")
	tok := NewTokenizer(salt, nil)
	tok.HostnameMode, tok.IPMode = HostnameRot13, IPCGNAT
	rules := DefaultRedaction().Rules()
	rules.Key = hex.EncodeToString(salt)
	rd, _ := NewRedactor(rules)
	rd.OnMap = func(token, real string) { m.Add(token, "scrub", real) }
	recs := []inventory.Record{{Fields: map[string]string{"hostname": "fw01.cyberdyne.systems", "ip": "10.1.0.1", "comment": "internet exposed; mgmt via jump01.cyberdyne.systems from 10.1.0.1, auth using saml"}}}
	out := Apply(Policy{"hostname": Pseudonym, "ip": Pseudonym, "comment": Scrub}, tok, m, rd, recs)
	c := out[0].Fields["comment"]
	if strings.Contains(c, "cyberdyne") || strings.Contains(c, "10.1.0.1") || !strings.Contains(c, "auth using saml") {
		t.Fatalf("scrub: %s", c)
	}
	// The comment's address matches the ip field token (same salt).
	if !strings.Contains(c, out[0].Fields["ip"]) {
		t.Errorf("comment address %q does not match ip token %q", c, out[0].Fields["ip"])
	}
	if m.Replace(c) != recs[0].Fields["comment"] {
		t.Errorf("not reversible: %s", m.Replace(c))
	}
	// nil redactor drops scrub fields.
	if _, ok := Apply(Policy{"comment": Scrub}, tok, m, nil, recs)[0].Fields["comment"]; ok {
		t.Error("scrub without redactor must drop")
	}
}
